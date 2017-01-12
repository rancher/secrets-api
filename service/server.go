package service

import (
	"net/http"
)

// StartServer creates and initializes the server api
func StartServer() error {
	router := NewRouter()
	return http.ListenAndServe(":8181", router)
}
