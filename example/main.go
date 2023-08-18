package main

import (
	"fmt"
	"html"
	"net/http"

	"github.com/jschwinger233/gofuncgraph/example/internal/log"
)

func main() {
	http.HandleFunc("/bar", handleBar)

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleBar(w http.ResponseWriter, r *http.Request) {
	log.Debug("received request for /bar")
	fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
}
