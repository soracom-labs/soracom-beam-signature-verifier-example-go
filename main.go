package main

import (
	"log"
	"net/http"
	"os"

	"github.com/2matzzz/soracom-beam-signature-verifier-example-go/soracom"
)

func app(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("valid"))
}

func main() {

	serverPort := os.Getenv("SERVER_PORT")
	mux := http.NewServeMux()

	mux.Handle("/", soracom.BeamSignatureVerifier(http.HandlerFunc(app)))

	err := http.ListenAndServe(":"+serverPort, mux)
	log.Fatal(err)
}
