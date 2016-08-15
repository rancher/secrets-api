package service

import (
	"net/http"
)

func StartServer() error {
	router := NewRouter()
	return http.ListenAndServe(":8181", router)
}
