package secrets

import (
	"github.com/rancher/go-rancher/client"
	"github.com/rancher/secrets-api/pkg/aesutils"
)

type SecretCollection struct {
	client.Collection
	Data []Secret `json:"data,omitempty"`
}

type BulkSecret struct {
	client.Resource
	Data      []Secret `json:"data,omitempty"`
	RewrapKey string   `json:"rewrapKey,omitempty"`
}

type Secret struct {
	client.Resource
	SecretName          string `json:"name"`
	Backend             string `json:"backend"`
	KeyName             string `json:"keyName"`
	CipherText          string `json:"cipherText,omitempty"`
	ClearText           string `json:"clearText,omitempty"`
	RewrapText          string `json:"rewrapText,omitempty"`
	RewrapKey           string `json:"rewrapKey,omitempty"`
	HashAlgorithm       string `json:"hashAlgorithm"`
	EncryptionAlgorithm string `json:"encryptionAglorigthm"`
	Signature           string `json:"signature"`
	tmpKey              aesutils.AESKey
}

type EncryptedData struct {
	EncryptionAlgorithm string           `json:"encryptionAlgorithm,omitempty"`
	EncryptedText       string           `json:"encryptedText,omitempty"`
	HashAlgorithm       string           `json:"hashAlgorithm,omitempty"`
	EncryptedKey        RSAEncryptedData `json:"encryptedKey,omitempty"`
	Signature           string           `json:"signature,omitempty"`
}

type RSAEncryptedData struct {
	EncryptionAlgorithm string `json:"encryptionAlgorithm,omitempty"`
	EncryptedText       string `json:"encryptedText,omitempty"`
	HashAlgorithm       string `json:"hashAlgorithm,omitempty"`
}
