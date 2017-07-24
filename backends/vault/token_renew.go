package vault

import (
	"github.com/Sirupsen/logrus"

	"github.com/hashicorp/vault/api"
)

// RenewLease renews the auth token for Vault
func RenewLease(c *api.Client) error {
	secret := &api.Secret{
		Auth: &api.SecretAuth{
			ClientToken: c.Token(),
			Renewable:   true,
		},
	}

	input := &api.RenewerInput{
		Secret: secret,
	}

	renewer, err := c.NewRenewer(input)
	if err != nil {
		return err
	}
	go renewer.Renew()
	defer renewer.Stop()
RENEW:
	for {
		select {
		case err := <-renewer.DoneCh():
			if err != nil {
				logrus.Warn("failed to renew: ", err)
			}
			logrus.Warn("renewer returned (maybe the lease expired)")
			break RENEW
		case renewal := <-renewer.RenewCh():
			logrus.Debug("vault token successfully renewed")
			if renewal.Secret.Warnings != nil {
				logrus.Warn(renewal.Secret.Warnings)
			}
		}
	}
	return nil
}
