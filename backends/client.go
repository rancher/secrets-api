package backends

import (
	"errors"

	"github.com/rancher/secrets-api/backends/localkey"
	"github.com/rancher/secrets-api/backends/none"
)

var runtimeConfigs *Configs

type EncryptorClient interface {
	GetEncryptedText(keyName string, clearText string) (string, error)
	GetClearText(keyName string, cipherText string) (string, error)
}

func New(name string) (EncryptorClient, error) {
	switch name {
	case "none":
		return &none.Client{}, nil
	case "localkey":
		if runtimeConfigs != nil {
			return localkey.NewLocalKeyAndInitBlock(runtimeConfigs.EncryptionKeyPath)
		}
		return nil, errors.New("No backend configured")
	default:
		return nil, errors.New("Unknown Encryption backend")
	}
}
