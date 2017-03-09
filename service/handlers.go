package service

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/Sirupsen/logrus"
	"github.com/rancher/go-rancher/api"
	"github.com/rancher/go-rancher/client"
	"github.com/rancher/secrets-api/secrets"
)

type errObj struct {
	client.Resource
	Status  string `json:"status,omitempty"`
	Message string `json:"message,omitempty"`
}

// ListSecrets to make schemas work better
func ListSecrets(w http.ResponseWriter, r *http.Request) (int, error) {
	apiContext := api.GetApiContext(r)
	secretCollection := &secrets.SecretCollection{
		Collection: client.Collection{
			ResourceType: "secret",
		},
	}
	secretCollection.Actions = map[string]string{
		"create":             apiContext.UrlBuilder.Collection("secret") + "/create",
		"rewrap":             apiContext.UrlBuilder.Collection("secret") + "/rewrap",
		"purge":              apiContext.UrlBuilder.Collection("secret") + "/purge",
		"rewrap?action=bulk": apiContext.UrlBuilder.Collection("secret") + "/rewrap?action=bulk",
		"create?action=bulk": apiContext.UrlBuilder.Collection("secret") + "/create?action=bulk",
		"purge?action=bulk":  apiContext.UrlBuilder.Collection("secret") + "/purge?action=bulk",
	}

	apiContext.Write(secretCollection)

	return http.StatusOK, nil
}

// CreateSecret POST handler for route /secrets to create a new secret
func CreateSecret(w http.ResponseWriter, r *http.Request) (int, error) {
	apiContext := api.GetApiContext(r)

	sec := secrets.NewSecret(apiContext)

	jsonDecoder := json.NewDecoder(r.Body)

	err := jsonDecoder.Decode(&sec)
	if err != nil {
		logrus.Errorf("Could not decode: %s because %s", r.Body, err)
		return http.StatusBadRequest, err
	}

	err = sec.Encrypt()
	if err != nil {
		logrus.Errorf("Could not encrypt secret")
		logrus.Error(err)
		return http.StatusBadRequest, err
	}

	apiContext.Write(&sec)

	return http.StatusOK, nil
}

// BulkCreateSecret handles creating a list of multiple secrets and generating response
func BulkCreateSecret(w http.ResponseWriter, r *http.Request) (int, error) {
	apiContext := api.GetApiContext(r)
	bulkSecret := secrets.NewBulkSecret()

	jsonDecoder := json.NewDecoder(r.Body)

	err := jsonDecoder.Decode(&bulkSecret)
	if err != nil {
		return http.StatusBadRequest, err
	}

	err = bulkSecret.Encrypt()
	if err != nil {
		logrus.Error(err)
		return http.StatusBadRequest, err
	}

	apiContext.Write(bulkSecret)
	return http.StatusOK, nil
}

// RewrapSecret rewraps a single secret witha  usersupplied public key
func RewrapSecret(w http.ResponseWriter, r *http.Request) (int, error) {
	apiContext := api.GetApiContext(r)

	sec := secrets.GetSecretResource()

	jsonDecoder := json.NewDecoder(r.Body)

	err := jsonDecoder.Decode(&sec)
	if err != nil {
		logrus.Errorf("Could not decode: %s because %s", r.Body, err)
		return http.StatusBadRequest, err
	}

	err = sec.Rewrap()
	if err != nil {
		logrus.Errorf("Could not rewrap secret")
		return http.StatusBadRequest, err
	}

	apiContext.Write(&sec)
	return http.StatusOK, nil
}

// BulkRewrapSecret rewraps multiple secrets with a single given public key
func BulkRewrapSecret(w http.ResponseWriter, r *http.Request) (int, error) {
	apiContext := api.GetApiContext(r)
	bulkSecret := secrets.NewBulkSecret()

	jsonDecoder := json.NewDecoder(r.Body)

	err := jsonDecoder.Decode(&bulkSecret)
	if err != nil {
		logrus.Errorf("Could not decode: %s because %s", r.Body, err)
		return http.StatusBadRequest, err
	}

	err = bulkSecret.Rewrap()
	if err != nil {
		logrus.Error(err)
		return http.StatusBadRequest, err
	}

	apiContext.Write(&bulkSecret)
	return http.StatusOK, nil
}

// DeleteSecret provides a hook to the backend to clear out data.
func DeleteSecret(w http.ResponseWriter, r *http.Request) (int, error) {
	sec := secrets.GetSecretResource()

	jsonDecoder := json.NewDecoder(r.Body)

	err := jsonDecoder.Decode(&sec)
	if err != nil {
		logrus.Errorf("Could not decode: %s because %s", r.Body, err)
		return http.StatusBadRequest, err
	}

	err = sec.Delete()
	if err != nil {
		logrus.Error(err)
		return http.StatusBadRequest, err
	}

	return http.StatusNoContent, nil
}

// BulkDeleteSecret provides a hook to the backend to clear out data.
func BulkDeleteSecret(w http.ResponseWriter, r *http.Request) (int, error) {
	bulkSecret := secrets.NewBulkSecret()

	jsonDecoder := json.NewDecoder(r.Body)

	err := jsonDecoder.Decode(&bulkSecret)
	if err != nil {
		logrus.Errorf("Could not decode: %s because %s", r.Body, err)
		return http.StatusBadRequest, err
	}

	err = bulkSecret.Delete()
	if err != nil {
		logrus.Error(err)
		return http.StatusBadRequest, err
	}

	return http.StatusNoContent, nil
}

//URLEncoded encodes the urls so that spaces are allowed in resource names
func URLEncoded(str string) string {
	u, err := url.Parse(str)
	if err != nil {
		logrus.Errorf("Error encoding the url: %s , error: %v", str, err)
		return str
	}
	return u.String()
}
