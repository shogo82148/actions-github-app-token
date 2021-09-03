package main

import (
	"errors"
	"log"
	"net/http"

	githubapptoken "github.com/shogo82148/actions-github-app-token/provider/github-app-token"
	"github.com/shogo82148/ridgenative"
)

func main() {
	h, err := githubapptoken.NewHandler()
	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/", h)
	err = ridgenative.ListenAndServe(":8080", nil)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
