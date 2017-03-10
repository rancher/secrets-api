package secrets

import (
	"github.com/Sirupsen/logrus"
	"github.com/rancher/go-rancher/client"
	"github.com/rancher/secrets-api/pkg/aesutils"
)

func NewBulkSecretInput() *BulkSecretInput {

	return &BulkSecretInput{
		Resource: client.Resource{
			Type: "bulkSecretInput",
		},
		Data: []*UnencryptedSecret{},
	}
}

func GetBulkEncryptedSecretResource() *BulkEncryptedSecret {
	return &BulkEncryptedSecret{}
}

func NewBulkEncryptedSecret(secretInput *BulkSecretInput) (*BulkEncryptedSecret, error) {
	bsi := &BulkEncryptedSecret{
		Resource: client.Resource{
			Type: "bulkEncryptedSecret",
		},
		Data: []*EncryptedSecret{},
	}

	return bsi, bsi.seal(secretInput.Data)
}

func NewBulkRewrappedSecret(secrets *BulkEncryptedSecret) (*BulkRewrappedSecret, error) {
	brs := &BulkRewrappedSecret{
		Resource: client.Resource{
			Type: "bulkRewrappedSecret",
		},
	}

	return brs, brs.rewrap(secrets)
}

func (bes *BulkEncryptedSecret) Delete() error {
	for _, secret := range bes.Data {
		err := secret.Delete()
		if err != nil {
			logrus.Error(err)
			return err
		}
	}

	return nil
}

func (s *BulkRewrappedSecret) rewrap(secrets *BulkEncryptedSecret) error {
	tmpKey, err := aesutils.NewRandomAESKey(32)
	if err != nil {
		return err
	}

	for _, secret := range secrets.Data {
		secret.SetTmpKey(tmpKey)
		secret.RewrapKey = secrets.RewrapKey

		rewrapped, err := NewRewrappedSecret(secret)
		if err != nil {
			logrus.Errorf("Could not decrypt secret")
			return err
		}
		s.Data = append(s.Data, rewrapped)
	}

	return nil
}

func (bes *BulkEncryptedSecret) seal(clearData []*UnencryptedSecret) error {
	for _, clear := range clearData {
		secret, err := NewEncryptedSecret(clear)
		if err != nil {
			logrus.Error(err)
			return err
		}
		bes.Data = append(bes.Data, secret)
	}
	return nil
}
