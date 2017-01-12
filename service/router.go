package service

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/rancher/go-rancher/api"
	"github.com/rancher/go-rancher/client"
	"github.com/rancher/secrets-api/secrets"
)

var schemas *client.Schemas

// HandleError is a wrapper that handles response codes and error messages
func HandleError(s *client.Schemas, t func(http.ResponseWriter, *http.Request) (int, error)) http.Handler {
	return api.ApiHandler(s, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if code, err := t(rw, req); err != nil {
			logrus.Errorf("Error in request, code : %d: %s", code, err)
			apiContext := api.GetApiContext(req)
			rw.WriteHeader(code)

			apiContext.Write(&errObj{
				Resource: client.Resource{
					Type: "error",
				},
				Status:  strconv.Itoa(code),
				Message: err.Error(),
			})
		}
	}))
}

// NewRouter creates the router for the application and wires up Rancher API spec schema
func NewRouter() *mux.Router {
	schemas = &client.Schemas{}
	f := HandleError

	schemas.AddType("apiVersion", client.Resource{})
	schemas.AddType("schema", client.Schema{})
	schemas.AddType("bulkSecret", secrets.BulkSecret{})

	secret := schemas.AddType("secret", secrets.Secret{})
	secret.CollectionMethods = []string{"GET"}
	secret.CollectionActions = map[string]client.Action{
		"rewrap": {
			Input:  "secret",
			Output: "secret",
		},
		"rewrap?action=bulk": {
			Input:  "bulkSecret",
			Output: "bulkSecret",
		},
		"create": {
			Input:  "secret",
			Output: "secret",
		},
		"create?action=bulk": {
			Input:  "bulkSecret",
			Output: "bulkSecret",
		},
	}

	router := mux.NewRouter().StrictSlash(false)

	//Rancher Routes
	router.Methods("GET").Path("/v1-secrets").Handler(api.VersionHandler(schemas, "v1-secrets"))
	router.Methods("GET").Path("/v1-secrets/").Handler(api.VersionHandler(schemas, "v1-secrets"))

	router.Methods("GET").Path("/v1-secrets/schemas").Handler(api.SchemasHandler(schemas))
	router.Methods("GET").Path("/v1-secrets/schemas/").Handler(api.SchemasHandler(schemas))

	router.Methods("GET").Path("/v1-secrets/schemas/{id}").Handler(api.SchemaHandler(schemas))
	router.Methods("GET").Path("/v1-secrets/schemas/{id}/").Handler(api.SchemaHandler(schemas))

	router.Methods("GET").Path("/v1-secrets/secrets").Handler(f(schemas, ListSecrets))
	router.Methods("GET").Path("/v1-secrets/secrets/").Handler(f(schemas, ListSecrets))

	err := schemas.AddType("error", errObj{})
	err.CollectionMethods = []string{}

	//Application Routes -- Order matters here
	router.Methods("POST").
		Path("/v1-secrets/secrets/create").
		Queries("action", "bulk").
		Handler(f(schemas, BulkCreateSecret))

	router.Methods("POST").Path("/v1-secrets/secrets/create").Handler(f(schemas, CreateSecret))

	router.Methods("POST").
		Path("/v1-secrets/secrets/rewrap").
		Queries("action", "bulk").
		Handler(f(schemas, BulkRewrapSecret))

	router.Methods("POST").Path("/v1-secrets/secrets/rewrap").Handler(f(schemas, RewrapSecret))

	// These just loop back to themselves in the schemas
	router.Methods("GET").Path("/v1-secrets/secrets/create").Handler(f(schemas, ListSecrets))
	router.Methods("GET").Path("/v1-secrets/secrets/create/").Handler(f(schemas, ListSecrets))

	router.Methods("GET").Path("/v1-secrets/secrets/rewrap").Handler(f(schemas, ListSecrets))
	router.Methods("GET").Path("/v1-secrets/secrets/rewrap/").Handler(f(schemas, ListSecrets))

	router.Methods("GET").Path("/v1-secrets/secrets/create").Queries("action", "bulk").Handler(f(schemas, ListSecrets))
	router.Methods("GET").Path("/v1-secrets/secrets/create/").Queries("action", "bulk").Handler(f(schemas, ListSecrets))
	router.Methods("GET").Path("/v1-secrets/secrets/rewrap").Queries("action", "bulk").Handler(f(schemas, ListSecrets))
	router.Methods("GET").Path("/v1-secrets/secrets/rewrap/").Queries("action", "bulk").Handler(f(schemas, ListSecrets))

	router.NotFoundHandler = f(schemas, func(w http.ResponseWriter, req *http.Request) (int, error) {
		return 404, errors.New("Not found")
	})

	return router
}
