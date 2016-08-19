package backends

import (
	"errors"

	"github.com/rancher/secrets-api/backends/none"
)

type EncryptorClient interface {
	GetEncryptedText(keyName string, clearText string) (string, error)
	GetClearText(keyName string, cipherText string) (string, error)
}

func New(name string) (EncryptorClient, error) {
	switch name {
	case "none":
		return &none.Client{}, nil
	default:
		return nil, errors.New("Unknown Encryption backend")
	}
}
