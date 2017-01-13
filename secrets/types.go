package secrets

import (
	"crypto/rsa"

	"github.com/rancher/go-rancher/client"
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
	CipherText          string `json:"cipherText"`
	ClearText           string `json:"clearText"`
	RewrapText          string `json:"rewrapText"`
	RewrapKey           string `json:"rewrapKey,omitempty"`
	HashAlgorithm       string `json:"hashAlgorithm"`
	EncryptionAlgorithm string `json:"encryptionAglorigthm"`
	Signature           string `json:"signature"`
}

type rsaPublicKey struct {
	*rsa.PublicKey
}

type encryptedData struct {
	EncryptionAlgorithm string
	EncryptedText       string
	HashAlgorithm       string
}
