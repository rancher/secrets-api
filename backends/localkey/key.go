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
	keys     map[string][]byte
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
		keys:     map[string][]byte{},
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

	// If we have seen the key, return it from mem
	if k, ok := kf.keys[keyFile]; ok {
		return k, nil
	}

	// Load the key from disk
	key, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return []byte{}, err
	}

	// Save the Key to mem to avoid future IO.
	kf.keys[keyFile] = key

	return key, nil
}
