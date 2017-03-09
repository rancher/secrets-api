package secrets

import (
	"errors"

	"encoding/base64"
	"encoding/json"

	"github.com/rancher/go-rancher/api"
	"github.com/rancher/go-rancher/client"
	"github.com/rancher/secrets-api/backends"
	"github.com/rancher/secrets-api/pkg/aesutils"
	"github.com/rancher/secrets-api/pkg/rsautils"
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
	var err error
	if s.tmpKey == nil {
		if s.tmpKey, err = aesutils.NewRandomAESKey(32); err != nil {
			return err
		}
	}
	return s.clean(s.rewrap)
}

func (s *Secret) Delete() error {
	backend, err := backends.New(s.Backend)
	if err != nil {
		return err
	}

	return backend.Delete(s.KeyName, s.CipherText)
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

	s.HashAlgorithm = encData.HashAlgorithm
	s.EncryptionAlgorithm = encData.EncryptionAlgorithm

	// Marshal to bytes
	marshalledEncData, err := json.Marshal(encData)
	if err != nil {
		return err
	}

	// Marshal to string, things get weird in the wild.
	s.RewrapText = base64.StdEncoding.EncodeToString(marshalledEncData)

	s.CipherText = ""
	s.RewrapKey = ""

	return nil
}

func (s *Secret) wrapPlainText() (*EncryptedData, error) {
	backend, err := backends.New(s.Backend)
	if err != nil {
		return nil, err
	}

	clearText, err := backend.GetClearText(s.KeyName, s.CipherText)
	if err != nil {
		return nil, err
	}

	if match, err := backend.VerifySignature(s.KeyName, s.Signature, clearText); match && err == nil {
		return createMessageEnvelope(s.RewrapKey, clearText, s.tmpKey)
	}

	return nil, errors.New("Signatures did not match")
}

func (s *Secret) SetTmpKey(key aesutils.AESKey) {
	s.tmpKey = key
}

func rsaEncryptKey(public *rsautils.RSAPublicKey, aes aesutils.AESKey) (*RSAEncryptedData, error) {
	key, err := aes.Key()
	if err != nil {
		return nil, err
	}

	rsaText, err := public.Encrypt(string(key))
	if err != nil {
		return nil, err
	}

	return &RSAEncryptedData{
		EncryptedText:       rsaText,
		EncryptionAlgorithm: "PKCS1_OAEP",
		HashAlgorithm:       "sha256",
	}, nil
}
