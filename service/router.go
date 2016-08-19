package service

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rancher/go-rancher/api"
	"github.com/rancher/go-rancher/client"
	"github.com/rancher/secrets-api/secrets"
)

var schemas *client.Schemas

func HandleError(s *client.Schemas, t func(http.ResponseWriter, *http.Request) error) http.Handler {
	return api.ApiHandler(s, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if err := t(rw, req); err != nil {
			apiContext := api.GetApiContext(req)
			apiContext.WriteErr(err)
		}
	}))
}

func NewRouter() *mux.Router {
	schemas = &client.Schemas{}
	f := HandleError

	apiVersion := schemas.AddType("apiVersion", client.Resource{})
	apiVersion.CollectionMethods = []string{}

	schemas.AddType("schema", client.Schema{})

	secret := schemas.AddType("secret", secrets.Secret{})
	secret.CollectionMethods = []string{}
	secret.CollectionActions = map[string]client.Action{
		"rewrap": {
			Input:  "secret",
			Output: "secret",
		},
		"create": {
			Input:  "secret",
			Output: "secret",
		},
	}

	router := mux.NewRouter().StrictSlash(true)

	//Rancher Routes
	router.Methods("GET").Path("/").Handler(api.VersionHandler(schemas, "v1-secrets"))
	router.Methods("GET").Path("/v1-secrets/schemas").Handler(api.SchemasHandler(schemas))
	router.Methods("GET").Path("/v1-secrets/schemas/{id}").Handler(api.SchemaHandler(schemas))
	router.Methods("GET").Path("/v1-secrets").Handler(api.VersionHandler(schemas, "v1"))

	err := schemas.AddType("error", errObj{})
	err.CollectionMethods = []string{}

	//Application Routes

	router.Methods("POST").Path("/v1-secrets/secrets/create").Handler(f(schemas, CreateSecret))
	router.Methods("POST").Path("/v1-secrets/secrets/rewrap").Handler(f(schemas, RewrapSecret))

	return router
}
