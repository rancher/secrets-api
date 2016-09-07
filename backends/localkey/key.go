package localkey

import (
	"io/ioutil"

	"github.com/Sirupsen/logrus"
)

type encryptionKey interface {
	Key() ([]byte, error)
}

type keyFile struct {
	pathName string
}

func newEncryptionKey(keyType, keyPath string) encryptionKey {
	return &keyFile{
		pathName: keyPath,
	}
}

func (kf *keyFile) Key() ([]byte, error) {
	key, err := kf.readPrivateKey()
	if err != nil {
		return []byte{}, err
	}

	return key, nil
}

func (kf *keyFile) readPrivateKey() ([]byte, error) {
	keyData, err := ioutil.ReadFile(kf.pathName)
	if err != nil {
		return []byte{}, err
	}

	logrus.Debugf("Key: %s", string(keyData))
	return keyData, nil
}
