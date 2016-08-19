package secrets

import (
	"github.com/rancher/go-rancher/client"
)

type Secret struct {
	client.Resource
	Backend    string `json:"backend"`
	KeyName    string `json:"keyName"`
	CipherText string `json:"cipherText"`
	ClearText  string `json:"clearText"`
	ReWrapKey  string `json:"rewrapKey"`
}
