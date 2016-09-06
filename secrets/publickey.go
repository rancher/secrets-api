package secrets

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"

	"github.com/Sirupsen/logrus"
)

func newPublicKey(pKey string) (*rsaPublicKey, error) {
	key, err := loadRSAPublicKey(pKey)
	return &rsaPublicKey{key}, err
}

func (pk *rsaPublicKey) encrypt(text string) (*encryptedData, error) {
	rng := rand.Reader
	cipherText, err := rsa.EncryptOAEP(sha256.New(), rng, pk.PublicKey, []byte(text), []byte(""))

	return &encryptedData{
		EncryptionAlgorithm: "RSA-PKCS1-OAEP",
		EncryptedText:       base64.StdEncoding.EncodeToString(cipherText),
		HashAlgorithm:       "sha256",
	}, err
}

func loadRSAPublicKey(key string) (*rsa.PublicKey, error) {
	block, val := pem.Decode([]byte(key))
	if block == nil {
		logrus.Debugf(string(val))
		return nil, errors.New("Could not decode public key block")
	}
	logrus.Debugf("Public Key Block Type: %s", block.Type)

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pub.(*rsa.PublicKey), nil
}
