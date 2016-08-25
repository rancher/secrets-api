package secrets

import (
	"encoding/base64"

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
	var err error
	encData, err := s.wrapPlainText()
	if err != nil {
		return err
	}
	s.RewrapText = base64.StdEncoding.EncodeToString([]byte(encData.EncryptedText))
	s.HashAlgorithm = encData.Algorithm
	s.CipherText = ""
	s.ClearText = ""

	return nil
}

func (s *Secret) wrapPlainText() (*encryptedData, error) {
	pubKey, err := newPublicKey(s.RewrapKey)
	if err != nil {
		return nil, err
	}

	backend, err := backends.New(s.Backend)
	if err != nil {
		return nil, err
	}

	clearText, err := backend.GetClearText(s.KeyName, s.CipherText)
	if err != nil {
		return nil, err
	}

	return pubKey.encrypt(clearText)
}
