package main

import (
	"net/http"

	githubapptoken "github.com/shogo82148/actions-github-app-token/provider/github-app-token"
	"github.com/shogo82148/ridgenative"
)

func main() {
	h := githubapptoken.NewHandler()
	http.Handle("/", h)
	ridgenative.ListenAndServe(":8080", nil)
}
