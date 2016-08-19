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
	Resource client.Resource
	Status   string
	Message  string
}

// CreateSecret POST handler for route /secrets to create a new secret
func CreateSecret(w http.ResponseWriter, r *http.Request) error {
	apiContext := api.GetApiContext(r)

	sec := secrets.NewSecret(apiContext)

	jsonDecoder := json.NewDecoder(r.Body)

	err := jsonDecoder.Decode(&sec)
	if err != nil {
		logrus.Errorf("Could not decode: %s because %s", r.Body, err)
		return err
	}

	err = sec.Encrypt()
	if err != nil {
		logrus.Errorf("Could not encrypt secret")
		logrus.Error(err)
	}

	apiContext.Write(&sec)

	return nil
}

func RewrapSecret(w http.ResponseWriter, r *http.Request) error {
	apiContext := api.GetApiContext(r)

	sec := secrets.GetSecretResource()

	jsonDecoder := json.NewDecoder(r.Body)

	err := jsonDecoder.Decode(&sec)
	if err != nil {
		logrus.Errorf("Could not decode: %s because %s", r.Body, err)
		return err
	}

	err = sec.Rewrap()
	if err != nil {
		logrus.Errorf("Could not decrypt secret")
		return err
	}

	apiContext.Write(&sec)
	return nil
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
