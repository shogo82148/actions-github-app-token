package githubapptoken

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
)

type Handler struct{}

func NewHandler() *Handler {
	return &Handler{}
}

type requestBody struct {
	GitHubToken string `json:"github_token"`
}

type responseBody struct {
	Message string `json:"message,omitempty"`
	Warning string `json:"warning,omitempty"`
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
	ctx := r.Context()

	data, err := io.ReadAll(r.Body)
	if err != nil {
		h.handleError(w, r, fmt.Errorf("failed to read the request body: %w", err))
		return
	}
	var payload *requestBody
	if err := json.Unmarshal(data, &payload); err != nil {
		h.handleError(w, r, &validationError{
			message: fmt.Sprintf("failed to unmarshal the request body: %v", err),
		})
		return
	}

	resp, err := h.handle(ctx, payload)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("failed to write the response: %v", err)
	}
}

func (h *Handler) handle(ctx context.Context, req *requestBody) (*responseBody, error) {
	return &responseBody{}, nil
}

func (h *Handler) handleError(w http.ResponseWriter, r *http.Request, err error) {
	log.Println(err)
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
