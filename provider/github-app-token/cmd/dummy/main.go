package main

import (
	"net/http"

	githubapptoken "github.com/shogo82148/actions-github-app-token/provider/github-app-token"
)

func main() {
	h := githubapptoken.NewDummyHandler()
	http.Handle("/", h)
	http.ListenAndServe(":8080", nil)
}
