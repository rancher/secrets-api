package secrets

import (
	"errors"

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

func (s *Secret) clean(f func() error) error {
	err := f()
	s.ClearText = ""
	return err
}

// Encrypt implements the interface and uses a wrapper
// to ensure that clear text doesn't leave
func (s *Secret) Encrypt() error {
	return s.clean(s.encrypt)
}

// Rewrap implements the interface and uses a wrapper
// to ensure that clear text doesn't leave
func (s *Secret) Rewrap() error {
	return s.clean(s.rewrap)
}

func (s *Secret) encrypt() error {
	if _, err := base64.StdEncoding.DecodeString(s.ClearText); err != nil {
		s.ClearText = base64.StdEncoding.EncodeToString([]byte(s.ClearText))
	}

	backend, err := backends.New(s.Backend)
	if err != nil {
		return err
	}

	s.CipherText, err = backend.GetEncryptedText(s.KeyName, s.ClearText)
	if err != nil {
		return err
	}

	s.Signature, err = backend.Sign(s.KeyName, s.ClearText)
	if err != nil {
		return err
	}

	return nil
}

func (s *Secret) rewrap() error {
	var err error
	encData, err := s.wrapPlainText()
	if err != nil {
		return err
	}

	s.RewrapText = encData.EncryptedText
	s.HashAlgorithm = encData.HashAlgorithm
	s.EncryptionAlgorithm = encData.EncryptionAlgorithm

	s.CipherText = ""

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

	if match, err := backend.VerifySignature(s.KeyName, s.Signature, clearText); match && err == nil {
		return pubKey.encrypt(clearText)
	}

	return nil, errors.New("Signatures did not match")
}
