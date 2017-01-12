package localkey

import (
	"errors"
	"io/ioutil"
	"os"

	"github.com/Sirupsen/logrus"
)

type encryptionKey interface {
	Key(name string) ([]byte, error)
	//Key() ([]byte, error)
}

type keyFile struct {
	pathName string
	isDir    bool
}

func newEncryptionKey(keyPath string) (encryptionKey, error) {
	isDir, err := testIsDir(keyPath)
	if err != nil {
		return &keyFile{}, err
	}

	return &keyFile{
		pathName: keyPath,
		isDir:    isDir,
	}, nil
}

func testIsDir(keyPath string) (bool, error) {
	result := false

	file, err := os.Open(keyPath)
	if err != nil {
		return result, err
	}
	defer file.Close()

	fs, err := file.Stat()
	if err != nil {
		return result, err
	}

	return fs.IsDir(), nil
}

func (kf *keyFile) Key(keyName string) ([]byte, error) {
	if !kf.isDir {
		key, err := kf.readPrivateKey()
		if err != nil {
			return []byte{}, err
		}

		return key, nil
	}
	return []byte{}, errors.New("No key found in directory")
}

func (kf *keyFile) readPrivateKey() ([]byte, error) {
	keyData, err := ioutil.ReadFile(kf.pathName)
	if err != nil {
		return []byte{}, err
	}

	logrus.Debugf("Key: %s", string(keyData))
	return keyData, nil
}
