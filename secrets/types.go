package secrets

import (
	"crypto/rsa"

	"github.com/rancher/go-rancher/client"
)

type Secret struct {
	client.Resource
	Backend       string `json:"backend"`
	KeyName       string `json:"keyName"`
	CipherText    string `json:"cipherText"`
	ClearText     string `json:"clearText"`
	RewrapText    string `json:"rewrapText"`
	RewrapKey     string `json:"rewrapKey"`
	HashAlgorithm string `json:"hashAlgorithm"`
}

type rsaPublicKey struct {
	*rsa.PublicKey
}

type encryptedData struct {
	EncryptedText string
	Algorithm     string
}
