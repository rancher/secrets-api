package service

import (
	"net/http"
)

// StartServer creates and initializes the server api
func StartServer(listenAddress string) error {
	router := NewRouter()
	return http.ListenAndServe(listenAddress, router)
}
