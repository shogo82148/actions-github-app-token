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
	"github.com/shogo82148/actions-github-app-token/provider/github-app-token/github"
	"github.com/shogo82148/aws-xray-yasdk-go/xray"
	log "github.com/shogo82148/ctxlog"
)

// the sentinel error that the token is not GITHUB_TOKEN
var errNotGitHubToken = errors.New("githubapptoken: the token is not GITHUB_TOKEN")

type githubClient interface {
	GetApp(ctx context.Context) (*github.GetAppResponse, error)
	CreateStatus(ctx context.Context, token, owner, repo, ref string, status *github.CreateStatusRequest) (*github.CreateStatusResponse, error)
	GetReposInstallation(ctx context.Context, owner, repo string) (*github.GetReposInstallationResponse, error)
	CreateAppAccessToken(ctx context.Context, installationID uint64, permissions *github.CreateAppAccessTokenRequest) (*github.CreateAppAccessTokenResponse, error)
	ValidateAPIURL(url string) error
	ParseIDToken(ctx context.Context, idToken string) (*github.ActionsIDToken, error)
}

const (
	commitStatusContext = "github-app-token"
	creatorLogin        = "github-actions[bot]"
	creatorID           = 41898282
	creatorType         = "Bot"
)

type Handler struct {
	github githubClient
	app    *github.GetAppResponse
}

func NewHandler() (*Handler, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	c, err := github.NewClient(nil, appID, privateKey)
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
	}, nil
}

type requestBody struct {
	Repository string `json:"repository"`
	SHA        string `json:"sha"`
	APIURL     string `json:"api_url"`
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
	traceID := xray.ContextTraceID(ctx)
	ctx = log.With(ctx, log.Fields{
		"amzn_trace_id": traceID,
	})

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
	var err error
	var owner, repo string
	err = h.validateGitHubToken(ctx, token, req)
	if err == nil {
		owner, repo, err = splitOwnerRepo(req.Repository)
		if err != nil {
			return nil, err
		}
	} else if errors.Is(err, errNotGitHubToken) {
		id, err := h.github.ParseIDToken(ctx, token)
		if err != nil {
			return nil, &validationError{
				message: fmt.Sprintf("invalid JSON Web Token: %s", err.Error()),
			}
		}
		owner, repo, err = splitOwnerRepo(id.Repository)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}

	// issue a new access token
	inst, err := h.github.GetReposInstallation(ctx, owner, repo)
	if err != nil {
		var ghErr *github.ErrUnexpectedStatusCode
		if errors.As(err, &ghErr) && ghErr.StatusCode == http.StatusNotFound {
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
	resp, err := h.github.CreateAppAccessToken(ctx, inst.ID, &github.CreateAppAccessTokenRequest{
		Repositories: []string{repo},
	})
	if err != nil {
		return nil, fmt.Errorf("failed create access token: %w", err)
	}

	return &responseBody{
		GitHubToken: resp.Token,
	}, nil
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

func (h *Handler) validateGitHubToken(ctx context.Context, token string, req *requestBody) error {
	// early check of the token prefix
	// ref. https://github.blog/changelog/2021-03-31-authentication-token-format-updates-are-generally-available/
	if len(token) < 4 {
		return &validationError{
			message: "GITHUB_TOKEN has invalid format",
		}
	}
	switch token[:4] {
	case "ghp_":
		// Personal Access Tokens
		return &validationError{
			message: "GITHUB_TOKEN looks like Personal Access Token. `github-token` must be `${{ github.token }}` or `${{ secrets.GITHUB_TOKEN }}`.",
		}
	case "gho_":
		// OAuth Access tokens
		return &validationError{
			message: "GITHUB_TOKEN looks like OAuth Access token. `github-token` must be `${{ github.token }}` or `${{ secrets.GITHUB_TOKEN }}`.",
		}
	case "ghu_":
		// GitHub App user-to-server tokens
		return &validationError{
			message: "GITHUB_TOKEN looks like GitHub App user-to-server token. `github-token` must be `${{ github.token }}` or `${{ secrets.GITHUB_TOKEN }}`.",
		}
	case "ghs_":
		// GitHub App server-to-server tokens
		// It's OK
	case "ghr_":
		// GitHub App refresh tokens
		return &validationError{
			message: "GITHUB_TOKEN looks like GitHub App refresh token. `github-token` must be `${{ github.token }}` or `${{ secrets.GITHUB_TOKEN }}`.",
		}
	default:
		// it doesn't look a GitHub token.
		return errNotGitHubToken
	}
	resp, err := h.updateCommitStatus(ctx, token, req, &github.CreateStatusRequest{
		State:       github.CommitStateSuccess,
		Description: "valid GitHub token",
		Context:     commitStatusContext,
	})
	if err != nil {
		var githubErr *github.ErrUnexpectedStatusCode
		if errors.As(err, &githubErr) {
			if 400 <= githubErr.StatusCode && githubErr.StatusCode < 500 {
				return &validationError{
					message: "Your GITHUB_TOKEN doesn't have enough permission. Write-Permission is required.",
				}
			}
		}
		return err
	}
	if resp.Creator.Login != creatorLogin || resp.Creator.ID != creatorID || resp.Creator.Type != creatorType {
		return &validationError{
			message: fmt.Sprintf("`github-token` isn't be generated by @%s. `github-token` must be `${{ github.token }}` or `${{ secrets.GITHUB_TOKEN }}`.", creatorLogin),
		}
	}
	return nil
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

func (h *Handler) updateCommitStatus(ctx context.Context, token string, req *requestBody, status *github.CreateStatusRequest) (*github.CreateStatusResponse, error) {
	owner, repo, err := splitOwnerRepo(req.Repository)
	if err != nil {
		return nil, err
	}
	return h.github.CreateStatus(ctx, token, owner, repo, req.SHA, status)
}
