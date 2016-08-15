package service

import (
	"github.com/gorilla/mux"
	"github.com/rancher/go-rancher/api"
	"github.com/rancher/go-rancher/client"
)

var schemas *client.Schemas

func NewRouter() *mux.Router {
	schemas = &client.Schemas{}

	apiVersion := schemas.AddType("apiVersion", client.Resource{})
	apiVersion.CollectionMethods = []string{}

	schemas.AddType("schema", client.Schema{})

	router := mux.NewRouter().StrictSlash(true)

	router.Methods("GET").Path("/v1/schemas").Handler(api.SchemasHandler(schemas))

	return router
}
