package secrets

import (
	"github.com/Sirupsen/logrus"
	"github.com/rancher/go-rancher/client"
)

func NewBulkSecret() *BulkSecret {

	return &BulkSecret{
		Resource: client.Resource{
			Type: "bulkSecret",
		},
		Data: []Secret{},
	}
}

func (s *BulkSecret) Rewrap() error {
	for idx, secret := range s.Data {
		secret.RewrapKey = s.RewrapKey
		err := secret.Rewrap()
		if err != nil {
			logrus.Errorf("Could not decrypt secret")
			return err
		}
		s.Data[idx] = secret
	}
	return nil
}

func (s *BulkSecret) Encrypt() error {
	for idx, secret := range s.Data {
		err := secret.Encrypt()
		if err != nil {
			logrus.Error(err)
			return err
		}
		s.Data[idx] = secret
	}
	return nil
}
