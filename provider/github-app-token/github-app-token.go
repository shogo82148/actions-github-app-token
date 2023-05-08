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
	"golang.org/x/sync/errgroup"
)

type githubClient interface {
	GetApp(ctx context.Context) (*github.GetAppResponse, error)
	GetReposInstallation(ctx context.Context, owner, repo string) (*github.GetReposInstallationResponse, error)
	GetRepo(ctx context.Context, token, owner, repo string) (*github.GetRepoResponse, error)
	GetReposInfo(ctx context.Context, token, nodeID string) (*github.GetReposInfoResponse, error)
	GetReposContent(ctx context.Context, token, owner, repo, path string) (*github.GetReposContentResponse, error)
	CreateAppAccessToken(ctx context.Context, installationID uint64, permissions *github.CreateAppAccessTokenRequest) (*github.CreateAppAccessTokenResponse, error)
	ValidateAPIURL(url string) error
	ParseIDToken(ctx context.Context, idToken string) (*github.ActionsIDToken, error)
	RevokeAppAccessToken(ctx context.Context, token string) error
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
	err     error
}

func (err *validationError) Error() string {
	return err.message
}

func (err *validationError) Unwrap() error {
	return err.err
}

type forbiddenError struct {
	err error
}

func (err *forbiddenError) Error() string {
	return "forbidden: " + err.err.Error()
}

func (err *forbiddenError) Unwrap() error {
	return err.err
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := log.With(r.Context(), log.Fields{
		"x-amzn-trace-id": xray.ContextTraceID(r.Context()),
	})

	if r.Method != http.MethodPost {
		h.handleMethodNotAllowed(w)
		return
	}

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

	repoID, err := strconv.ParseUint(id.RepositoryID, 10, 64)
	if err != nil {
		return nil, err
	}
	repoIDs, err := h.getRepositoryIDs(ctx, inst.ID, repoID, owner, repo, req.Repositories)
	if err != nil {
		return nil, err
	}

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

// contains returns true if the slice contains s.
func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// validateToken validates the token and returns the token's payload.
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

func (h *Handler) getRepositoryIDs(ctx context.Context, inst, repoID uint64, owner, repo string, nodeIDs []string) ([]uint64, error) {
	if len(nodeIDs) == 0 {
		return []uint64{repoID}, nil
	}

	resp, err := h.github.CreateAppAccessToken(ctx, inst, &github.CreateAppAccessTokenRequest{
		Permissions: &github.CreateAppAccessTokenRequestPermissions{
			SingleFile: "read",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed create access token: %w", err)
	}
	token := resp.Token
	defer h.github.RevokeAppAccessToken(ctx, token)

	detail, err := h.github.GetRepo(ctx, token, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("failed to get the repo: %w", err)
	}
	if detail.ID != repoID {
		return nil, fmt.Errorf("repo id is mismatch")
	}

	ch := make(chan uint64, len(nodeIDs))
	g, ctx := errgroup.WithContext(ctx)
	for _, nodeID := range nodeIDs {
		nodeID := nodeID
		if nodeID == "" {
			continue
		}
		ctx := log.With(ctx, log.Fields{
			"repository_node_id": nodeID,
		})
		g.Go(func() error {
			id, err := h.checkPermission(ctx, token, nodeID, detail.NodeID)
			if err != nil {
				log.Debug(ctx, "permission denied", log.Fields{
					"error": err.Error(),
				})
				return err
			}
			ch <- id
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, &forbiddenError{err: err}
	}
	close(ch)

	ret := make([]uint64, 0, len(nodeIDs)+1)
	ret = append(ret, repoID)
	for id := range ch {
		ret = append(ret, id)
	}
	return ret, nil
}

func (h *Handler) checkPermission(ctx context.Context, token, to, from string) (uint64, error) {
	log.Debug(ctx, "checking permission", nil)
	info, err := h.github.GetReposInfo(ctx, token, to)
	if err != nil {
		return 0, err
	}

	log.Debug(ctx, "fetching .github/actions.yaml", nil)
	resp, err := h.github.GetReposContent(ctx, token, info.Owner, info.Name, ".github/actions.yaml")
	if err == nil {
		return h.checkConfig(ctx, info, resp, from)
	} else if status, ok := githubStatusCode(err); !ok || status != http.StatusNotFound {
		return 0, fmt.Errorf("failed to fetch .github/actions.yaml: %w", err)
	}
	log.Debug(ctx, ".github/actions.yaml not found", nil)

	log.Debug(ctx, "fetching .github/actions.yml", nil)
	resp, err = h.github.GetReposContent(ctx, token, info.Owner, info.Name, ".github/actions.yml")
	if err == nil {
		return h.checkConfig(ctx, info, resp, from)
	} else if status, ok := githubStatusCode(err); !ok || status != http.StatusNotFound {
		return 0, fmt.Errorf("failed to fetch .github/actions.yml: %w", err)
	}
	log.Debug(ctx, ".github/actions.yml not found", nil)

	return 0, errors.New("config file is not found")
}

func (h *Handler) checkConfig(ctx context.Context, info *github.GetReposInfoResponse, resp *github.GetReposContentResponse, from string) (uint64, error) {
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

	for _, nodeID := range config.Repositories {
		if nodeID == from {
			return info.ID, nil
		}
	}
	return 0, errors.New("permission denied")
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

	var forbidden *forbiddenError
	if errors.As(err, &forbidden) {
		status = http.StatusForbidden
		body = &errorResponseBody{
			Message: "Permission denied. " +
				"Please check your repository has .github/actions.yaml",
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

// splitOwnerRepo splits full name into owner and repository name.
func splitOwnerRepo(fullname string) (owner, repo string, err error) {
	owner, repo, ok := strings.Cut(fullname, "/")
	if !ok {
		err = &validationError{
			message: fmt.Sprintf("invalid repository name: %s", fullname),
		}
		return
	}
	return
}

func githubStatusCode(err error) (int, bool) {
	var ghErr *github.UnexpectedStatusCodeError
	if errors.As(err, &ghErr) {
		return ghErr.StatusCode, true
	}
	return 0, false
}
