package githubapptoken

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/goccy/go-yaml"
	"github.com/shogo82148/actions-github-app-token/provider/github-app-token/github"
	"github.com/shogo82148/aws-xray-yasdk-go/xray"
	"github.com/shogo82148/aws-xray-yasdk-go/xrayhttp"
	log "github.com/shogo82148/ctxlog"
)

type githubClient interface {
	GetApp(ctx context.Context) (*github.GetAppResponse, error)
	GetReposInstallation(ctx context.Context, owner, repo string) (*github.GetReposInstallationResponse, error)
	GetReposInfo(ctx context.Context, token, nodeID string) (*github.GetReposInfoResponse, error)
	GetReposContent(ctx context.Context, token, owner, repo, path string) (*github.GetReposContentResponse, error)
	CreateAppAccessToken(ctx context.Context, installationID uint64, permissions *github.CreateAppAccessTokenRequest) (*github.CreateAppAccessTokenResponse, error)
	ValidateAPIURL(url string) error
	ParseIDToken(ctx context.Context, idToken string) (*github.ActionsIDToken, error)
}

const (
	audiencePrefix = "https://github-app.shogo82148.com/"
)

type Handler struct {
	github githubClient
	app    *github.GetAppResponse
	appID  uint64
}

func NewHandler() (*Handler, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, seg := xray.BeginDummySegment(ctx)
	defer seg.Close()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	svc := ssm.NewFromConfig(cfg)

	appIDParam, err := svc.GetParameter(ctx, &ssm.GetParameterInput{
		Name: aws.String(os.Getenv("GITHUB_APP_ID")),
	})
	if err != nil {
		return nil, err
	}
	appID, err := strconv.ParseUint(aws.ToString(appIDParam.Parameter.Value), 10, 64)
	if err != nil {
		return nil, err
	}

	privateKeyParam, err := svc.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(os.Getenv("GITHUB_PRIVATE_KEY")),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}
	privateKey := []byte(aws.ToString(privateKeyParam.Parameter.Value))

	client := xrayhttp.Client(http.DefaultClient)
	c, err := github.NewClient(client, appID, privateKey)
	if err != nil {
		return nil, err
	}

	app, err := c.GetApp(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get the app information, check your configure: %w", err)
	}

	return &Handler{
		github: c,
		app:    app,
		appID:  appID,
	}, nil
}

type requestBody struct {
	Repositories []string `json:"repositories"`
	APIURL       string   `json:"api_url"`
}

type responseBody struct {
	GitHubToken string `json:"github_token"`
	Message     string `json:"message,omitempty"`
	Warning     string `json:"warning,omitempty"`
}

type errorResponseBody struct {
	Message string `json:"message"`
}

type validationError struct {
	message string
}

func (err *validationError) Error() string {
	return err.message
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.handleMethodNotAllowed(w)
		return
	}

	ctx := r.Context()

	data, err := io.ReadAll(r.Body)
	if err != nil {
		h.handleError(ctx, w, r, fmt.Errorf("failed to read the request body: %w", err))
		return
	}
	var payload *requestBody
	if err := json.Unmarshal(data, &payload); err != nil {
		h.handleError(ctx, w, r, &validationError{
			message: fmt.Sprintf("failed to unmarshal the request body: %v", err),
		})
		return
	}
	token, err := h.getAuthToken(r.Header)
	if err != nil {
		h.handleError(ctx, w, r, err)
		return
	}

	resp, err := h.handle(ctx, token, payload)
	if err != nil {
		h.handleError(ctx, w, r, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Error(ctx, "failed to write the response", log.Fields{
			"error": err.Error(),
		})
	}
}

func (h *Handler) handle(ctx context.Context, token string, req *requestBody) (*responseBody, error) {
	if err := h.github.ValidateAPIURL(req.APIURL); err != nil {
		return nil, &validationError{
			message: err.Error(),
		}
	}

	// authorize the request
	id, err := h.validateToken(ctx, token)
	if err != nil {
		return nil, err
	}
	owner, repo, err := splitOwnerRepo(id.Repository)
	if err != nil {
		return nil, err
	}

	// issue a new access token
	inst, err := h.github.GetReposInstallation(ctx, owner, repo)
	if err != nil {
		if status, ok := githubStatusCode(err); ok && status == http.StatusNotFound {
			// installation not found.
			// the user may not install the app.
			return nil, &validationError{
				message: fmt.Sprintf(
					"Installation not found. "+
						"You need to install the GitHub App to use the action. "+
						"See %s for more detail",
					h.app.HTMLURL,
				),
			}
		}
		return nil, fmt.Errorf("failed to get resp's installation: %w", err)
	}

	repoIDs, err := h.getRepositoryIDs(ctx, inst.ID, req.Repositories)
	if err != nil {
		return nil, err
	}

	repoID, err := strconv.ParseUint(id.RepositoryID, 10, 64)
	if err != nil {
		return nil, err
	}
	repoIDs = append(repoIDs, repoID)
	resp, err := h.github.CreateAppAccessToken(ctx, inst.ID, &github.CreateAppAccessTokenRequest{
		RepositoryIDs: repoIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("failed create access token: %w", err)
	}

	return &responseBody{
		GitHubToken: resp.Token,
	}, nil
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func (h *Handler) validateToken(ctx context.Context, token string) (*github.ActionsIDToken, error) {
	id, err := h.github.ParseIDToken(ctx, token)
	if err != nil {
		return nil, &validationError{
			message: fmt.Sprintf("invalid JSON Web Token: %s", err.Error()),
		}
	}
	if !contains(id.Audience, fmt.Sprintf("%s%d", audiencePrefix, h.appID)) {
		return nil, &validationError{
			message: fmt.Sprintf("invalid audience: %v", id.Audience),
		}
	}
	return id, nil
}

func (h *Handler) getRepositoryIDs(ctx context.Context, inst uint64, nodeIDs []string) ([]uint64, error) {
	resp, err := h.github.CreateAppAccessToken(ctx, inst, &github.CreateAppAccessTokenRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed create access token: %w", err)
	}

	var ret []uint64
	token := resp.Token
	for _, nodeID := range nodeIDs {
		ctx := log.With(ctx, log.Fields{
			"repository_node_id": nodeID,
		})

		id, err := h.checkPermission(ctx, token, nodeID)
		if err != nil {
			log.Debug(ctx, "permission denied", log.Fields{
				"error": err.Error(),
			})
			return nil, err
		}
		ret = append(ret, id)
	}
	return ret, nil
}

func (h *Handler) checkPermission(ctx context.Context, token, nodeID string) (uint64, error) {
	log.Debug(ctx, "checking permission", nil)
	info, err := h.github.GetReposInfo(ctx, token, nodeID)
	if err != nil {
		return 0, err
	}

	log.Debug(ctx, "fetching .github/actions.yaml", nil)
	resp, err := h.github.GetReposContent(ctx, token, info.Owner, info.Name, ".github/actions.yaml")
	if err == nil {
		return h.checkConfig(ctx, info, resp)
	} else if status, ok := githubStatusCode(err); !ok || status != http.StatusNotFound {
		return 0, fmt.Errorf("failed to fetch .github/actions.yaml: %w", err)
	}
	log.Debug(ctx, ".github/actions.yaml not found", nil)

	log.Debug(ctx, "fetching .github/actions.yml", nil)
	resp, err = h.github.GetReposContent(ctx, token, info.Owner, info.Name, ".github/actions.yml")
	if err == nil {
		return h.checkConfig(ctx, info, resp)
	} else if status, ok := githubStatusCode(err); !ok || status != http.StatusNotFound {
		return 0, fmt.Errorf("failed to fetch .github/actions.yml: %w", err)
	}
	log.Debug(ctx, ".github/actions.yml not found", nil)

	return 0, errors.New("config file is not found")
}

func (h *Handler) checkConfig(ctx context.Context, info *github.GetReposInfoResponse, resp *github.GetReposContentResponse) (uint64, error) {
	content, err := resp.ParseFile()
	if err != nil {
		return 0, err
	}
	var config struct {
		Repositories []string `yaml:"repositories"`
	}
	if err := yaml.Unmarshal(content, &config); err != nil {
		return 0, err
	}

	// TODO: check config
	return info.ID, nil
}

func (h *Handler) handleError(ctx context.Context, w http.ResponseWriter, r *http.Request, err error) {
	log.Error(ctx, err.Error(), nil)
	status := http.StatusInternalServerError
	var body *errorResponseBody

	var validation *validationError
	if errors.As(err, &validation) {
		status = http.StatusBadRequest
		body = &errorResponseBody{
			Message: validation.message,
		}
	}

	if body == nil {
		body = &errorResponseBody{
			Message: "Internal Server Error",
		}
	}
	data, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(status)
	w.Write(data)
}

func (h *Handler) handleMethodNotAllowed(w http.ResponseWriter) {
	body := &errorResponseBody{
		Message: "Method Not Allowed",
	}
	data, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusMethodNotAllowed)
	w.Write(data)
}

func (h *Handler) getAuthToken(header http.Header) (string, error) {
	const prefix = "Bearer "
	v := header.Get("Authorization")
	if len(v) < len(prefix) {
		return "", &validationError{
			message: "invalid Authorization header",
		}
	}
	if !strings.EqualFold(v[:len(prefix)], prefix) {
		return "", &validationError{
			message: "invalid Authorization header",
		}
	}
	return v[len(prefix):], nil
}

func splitOwnerRepo(fullname string) (owner, repo string, err error) {
	idx := strings.IndexByte(fullname, '/')
	if idx < 0 {
		err = &validationError{
			message: fmt.Sprintf("invalid repository name: %s", fullname),
		}
		return
	}
	owner = fullname[:idx]
	repo = fullname[idx+1:]
	return
}

func githubStatusCode(err error) (int, bool) {
	var ghErr *github.UnexpectedStatusCodeError
	if errors.As(err, &ghErr) {
		return ghErr.StatusCode, true
	}
	return 0, false
}
