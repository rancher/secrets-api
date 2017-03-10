package secrets

import (
	"github.com/rancher/go-rancher/client"
	"github.com/rancher/secrets-api/pkg/aesutils"
)

type SecretCollection struct {
	client.Collection
	Data []Secret `json:"data,omitempty"`
}

type BulkSecretInput struct {
	client.Resource
	Data []*UnencryptedSecret `json:"data,omitempty"`
}

type BulkEncryptedSecret struct {
	client.Resource
	Data      []*EncryptedSecret `json:"data,omitempty"`
	RewrapKey string             `json:"rewrapKey,omitempty"`
}

type BulkRewrappedSecret struct {
	client.Resource
	Data []*RewrappedSecret `json:"data,omitempty"`
}

type UnencryptedSecret struct {
	client.Resource
	Backend   string `json:"backend"`
	KeyName   string `json:"keyName"`
	ClearText string `json:"clearText,omitempty"`
}

type EncryptedSecret struct {
	client.Resource
	Backend             string `json:"backend"`
	KeyName             string `json:"keyName"`
	CipherText          string `json:"cipherText,omitempty"`
	HashAlgorithm       string `json:"hashAlgorithm"`
	EncryptionAlgorithm string `json:"encryptionAglorigthm"`
	Signature           string `json:"signature"`
	RewrapKey           string `json:"rewrapKey,omitempty"`
	tmpKey              aesutils.AESKey
}

type RewrappedSecret struct {
	client.Resource
	SecretName string `json:"name,omitempty"`
	RewrapText string `json:"rewrapText,omitempty"`
}

type Secret struct {
	client.Resource
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
