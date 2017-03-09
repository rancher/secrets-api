package secrets

import (
	"github.com/Sirupsen/logrus"
	"github.com/rancher/go-rancher/client"
	"github.com/rancher/secrets-api/pkg/aesutils"
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
	tmpKey, err := aesutils.NewRandomAESKey(32)
	if err != nil {
		return err
	}
	for idx, secret := range s.Data {
		secret.RewrapKey = s.RewrapKey
		secret.SetTmpKey(tmpKey)

		err := secret.Rewrap()
		if err != nil {
			logrus.Errorf("Could not decrypt secret")
			return err
		}
		s.Data[idx] = secret
	}

	s.RewrapKey = ""

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

func (s *BulkSecret) Delete() error {
	for idx, secret := range s.Data {
		err := secret.Delete()
		if err != nil {
			logrus.Error(err)
			return err
		}
		s.Data[idx] = secret
	}
	return nil
}
