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

func GetEncryptedSecretResource() *EncryptedSecret {
	return &EncryptedSecret{}
}

func GetUnencryptedSecretResource() *UnencryptedSecret {
	return &UnencryptedSecret{}
}

func NewUnencryptedSecret(context *api.ApiContext) *UnencryptedSecret {
	return &UnencryptedSecret{
		Resource: client.Resource{
			Type: "secretInput",
		},
	}
}

func NewEncryptedSecret(clearSecret *UnencryptedSecret) (*EncryptedSecret, error) {
	secret := &EncryptedSecret{
		Resource: client.Resource{
			Type: "encryptedSecret",
		},
		Backend: clearSecret.Backend,
		KeyName: clearSecret.KeyName,
	}

	return secret, secret.seal(clearSecret.ClearText)
}

func NewRewrappedSecret(encSecret *EncryptedSecret) (*RewrappedSecret, error) {
	var err error

	secret := &RewrappedSecret{
		Resource: client.Resource{
			Type: "rewrappedSecret",
		},
	}

	if encSecret.tmpKey == nil {
		if encSecret.tmpKey, err = aesutils.NewRandomAESKey(32); err != nil {
			return secret, err
		}
	}

	secret.RewrapText, err = encSecret.rewrap()
	return secret, err
}

func (s *EncryptedSecret) Delete() error {
	backend, err := backends.New(s.Backend)
	if err != nil {
		return err
	}

	return backend.Delete(s.KeyName, s.CipherText)
}

func (s *EncryptedSecret) seal(clearText string) error {
	if _, err := base64.StdEncoding.DecodeString(clearText); err != nil {
		clearText = base64.StdEncoding.EncodeToString([]byte(clearText))
	}

	backend, err := backends.New(s.Backend)
	if err != nil {
		return err
	}

	s.CipherText, err = backend.GetEncryptedText(s.KeyName, clearText)
	if err != nil {
		return err
	}

	s.Signature, err = backend.Sign(s.KeyName, clearText)
	if err != nil {
		return err
	}

	return nil
}

func (s *EncryptedSecret) rewrap() (string, error) {
	var err error
	encData, err := s.wrapPlainText()
	if err != nil {
		return "", err
	}

	s.HashAlgorithm = encData.HashAlgorithm
	s.EncryptionAlgorithm = encData.EncryptionAlgorithm

	// Marshal to bytes
	marshalledEncData, err := json.Marshal(encData)
	if err != nil {
		return "", err
	}

	// Marshal to string, things get weird in the wild.
	data := base64.StdEncoding.EncodeToString(marshalledEncData)

	return data, nil
}

func (s *EncryptedSecret) wrapPlainText() (*EncryptedData, error) {
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

func (s *EncryptedSecret) SetTmpKey(key aesutils.AESKey) {
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
