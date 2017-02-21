package rsautils

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

// RSAPublicKey a struct to hold an RSA Public Key
type RSAPublicKey struct {
	*rsa.PublicKey
}

// PublicKeyFromString returns an RSA public key object from a string
func PublicKeyFromString(pKey string) (*RSAPublicKey, error) {
	key, err := loadRSAPublicKey(pKey)
	return &RSAPublicKey{key}, err
}

// Encrypt uses RSA Public key to encrypt data
func (pk *RSAPublicKey) Encrypt(text string) (string, error) {
	rng := rand.Reader
	cipherText, err := rsa.EncryptOAEP(sha256.New(), rng, pk.PublicKey, []byte(text), []byte(""))

	return base64.StdEncoding.EncodeToString(cipherText), err
}

func loadRSAPublicKey(key string) (*rsa.PublicKey, error) {
	block, val := pem.Decode([]byte(key))
	if block == nil {
		// This is supposed to be a public key so we can log
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
