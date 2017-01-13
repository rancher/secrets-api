package localkey

import (
	"io/ioutil"
	"os"
	"path"

	"github.com/Sirupsen/logrus"
)

type encryptionKey interface {
	Key(name string) ([]byte, error)
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
		logrus.Error(err)
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
	keyFile := keyName
	if kf.isDir {
		keyFile = path.Join(kf.pathName, keyName)
	}

	return ioutil.ReadFile(keyFile)
}
