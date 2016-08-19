package secrets

import (
	"github.com/rancher/go-rancher/api"
	"github.com/rancher/go-rancher/client"
	"github.com/rancher/secrets-api/backends"
)

func NewSecret(context *api.ApiContext) *Secret {
	secret := &Secret{
		Resource: client.Resource{
			Type: "secret",
		},
	}
	return secret
}

func GetSecretResource() *Secret {
	return &Secret{}
}

func (s *Secret) Encrypt() error {
	backend, err := backends.New(s.Backend)
	if err != nil {
		return err
	}

	s.CipherText, err = backend.GetEncryptedText(s.KeyName, s.ClearText)
	if err != nil {
		return err
	}

	s.ClearText = ""

	return nil
}

func (s *Secret) Rewrap() error {
	backend, err := backends.New(s.Backend)
	if err != nil {
		return err
	}

	s.ClearText, err = backend.GetClearText(s.KeyName, s.CipherText)
	if err != nil {
		return err
	}

	s.CipherText = ""

	return nil
}
