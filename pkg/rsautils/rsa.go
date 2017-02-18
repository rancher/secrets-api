package rsautils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

// Decryptor handles decrypting messages
type Decryptor interface {
	Decrypt(cipherText string) ([]byte, error)
}

type rsaDecryptor struct {
	privateKeyPath string
	key            *rsa.PrivateKey
}

//NewRSADecryptorKeyFromFile returns an RSA decryptor
func NewRSADecryptorKeyFromFile(privateKeyPath string) (Decryptor, error) {
	key, err := loadPrivateKeyFromFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	return rsaDecryptor{
		privateKeyPath: privateKeyPath,
		key:            key,
	}, nil
}

func NewRSADecryptorKeyFromString(privateKey string) (Decryptor, error) {
	key, err := loadPrivateKeyFromString(privateKey)
	if err != nil {
		return nil, err
	}

	return rsaDecryptor{
		privateKeyPath: "",
		key:            key,
	}, nil
}

//Decrypt implments the decryptor interface
func (r rsaDecryptor) Decrypt(cipherText string) ([]byte, error) {
	return rsaDecrypt(r.key, cipherText)
}

func loadPrivateKeyFromFile(keyPath string) (*rsa.PrivateKey, error) {
	keyData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New("Could not decode private key. Is it PEM format?")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func loadPrivateKeyFromString(keyString string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyString))
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func rsaDecrypt(priv *rsa.PrivateKey, cipherText string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return []byte{}, err
	}

	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, data, []byte(""))
}
