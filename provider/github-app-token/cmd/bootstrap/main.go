package main

import (
	"log/slog"
	"net/http"
	"os"

	githubapptoken "github.com/shogo82148/actions-github-app-token/provider/github-app-token"
	httplogger "github.com/shogo82148/go-http-logger"
	"github.com/shogo82148/ridgenative"
)

func main() {
	h, err := githubapptoken.NewHandler()
	if err != nil {
		slog.Error("failed to initialize: %v", err)
		os.Exit(1)
	}
	mux := http.NewServeMux()
	mux.Handle("/", h)

	logger := httplogger.NewSlogLogger(slog.LevelInfo, "message for http access", slog.Default())

	err = ridgenative.ListenAndServe(":8080", httplogger.LoggingHandler(logger, mux))
	if err != nil {
		slog.Error("failed to listen and serve: %v", err)
		os.Exit(1)
	}
}
