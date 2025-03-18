package main

import (
	"log/slog"
	"net/http"
	"os"

	githubapptoken "github.com/shogo82148/actions-github-app-token/provider/github-app-token"
	"github.com/shogo82148/aws-xray-yasdk-go/xray/xrayslog"
	httplogger "github.com/shogo82148/go-http-logger"
	"github.com/shogo82148/ridgenative"
)

var logger *slog.Logger

func init() {
	// initialize the logger
	h1 := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	h2 := xrayslog.NewHandler(h1, "trace_id")
	logger = slog.New(h2)
	slog.SetDefault(logger)
}

func main() {
	h, err := githubapptoken.NewHandler()
	if err != nil {
		slog.Error("failed to initialize", slog.Any("error", err))
		os.Exit(1)
	}
	mux := http.NewServeMux()
	mux.Handle("/", h)

	logger := httplogger.NewSlogLogger(slog.LevelInfo, "http access log", logger)

	err = ridgenative.ListenAndServe(":8080", httplogger.LoggingHandler(logger, mux))
	if err != nil {
		slog.Error("failed to listen and serve", slog.Any("error", err))
		os.Exit(1)
	}
}
