package aesutils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
)

type AESSecret struct {
	Nonce      []byte
	Algorithm  string
	CipherText []byte
}

func NewAESKeyFromFile(keyPath string) (AESKey, error) {
	return newEncryptionKey("file", keyPath), nil
}

func NewRandomAESKey(length int) (AESKey, error) {
	var err error
	if k, err := randomNonce(32); err == nil {
		return &randomKey{key: k}, nil
	}
	return nil, err
}

func NewAESKeyFromBytes(key []byte) AESKey {
	return &randomKey{key: key}
}

func InitBlock(aesKey AESKey) (cipher.Block, error) {
	key, err := aesKey.Key()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if block == nil {
		return nil, errors.New("Uninitialized Cipher Block")
	}

	return block, nil
}

// GetEncryptedText localkey Client just returns the cipherText
func GetEncryptedText(key AESKey, clearText string, algorithm string) (string, error) {
	secret := &AESSecret{
		Algorithm: "aes256-gcm",
	}

	cipherBlock, err := InitBlock(key)
	if err != nil {
		return "", err
	}

	nonce, err := randomNonce(12)
	if err != nil {
		return "", err
	}

	secret.Nonce = nonce

	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	secret.CipherText = gcm.Seal(nil, secret.Nonce, []byte(clearText), nil)

	jsonSecret, err := json.Marshal(secret)
	if err != nil {
		return "", err
	}

	return string(jsonSecret), nil
}

// GetClearText localkey Client just returns the clearText
func GetClearText(key AESKey, secretBlob string) (string, error) {
	secret := &AESSecret{}

	err := json.Unmarshal([]byte(secretBlob), secret)
	if err != nil {
		return "", err
	}

	cipherBlock, err := InitBlock(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	plainText, err := gcm.Open(nil, secret.Nonce, secret.CipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

func randomNonce(byteLength int) ([]byte, error) {
	key := make([]byte, byteLength)

	_, err := rand.Read(key)
	if err != nil {
		return []byte{}, err
	}

	return key, nil
}

func getB64RandomNonce(byteLength int) (string, error) {
	nonce, err := randomNonce(byteLength)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(nonce), nil
}
