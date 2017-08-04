package backends

import (
	"github.com/Sirupsen/logrus"
	"github.com/rancher/secrets-api/backends/vault"
)

type Configs struct {
	VaultToken        string
	VaultURL          string
	EncryptionKeyPath string
}

func NewConfig() *Configs {
	return &Configs{}
}

func SetBackendConfigs(config *Configs) error {
	runtimeConfigs = config
	if len(runtimeConfigs.VaultToken) != 0 {
		v, err := vault.NewClient(runtimeConfigs.VaultURL, runtimeConfigs.VaultToken)
		if err != nil {
			logrus.Error(err)
		}
		go v.RenewLease()
	}
	return nil
}
