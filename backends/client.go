package backends

import (
	"errors"

	"github.com/rancher/secrets-api/backends/localkey"
	"github.com/rancher/secrets-api/backends/none"
	"github.com/rancher/secrets-api/backends/vault"
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
		if runtimeConfigs.EncryptionKeyPath != "" {
			return localkey.NewLocalKeyAndInitBlock(runtimeConfigs.EncryptionKeyPath)
		}
		return nil, errors.New("No backend configured")
	case "vault":
		if runtimeConfigs.VaultURL != "" && runtimeConfigs.VaultToken != "" {
			return vault.NewClient(runtimeConfigs.VaultURL, runtimeConfigs.VaultToken)
		}
		return nil, errors.New("Backend not configured")
	default:
		return nil, errors.New("Unknown Encryption backend")
	}
}
