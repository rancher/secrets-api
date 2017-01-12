package localkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
)

// Client implements the backend client interface
type Client struct {
	encryptionKey encryptionKey
	cipher        cipher.Block
}

type internalSecret struct {
	Nonce      []byte
	Algorithm  string
	CipherText []byte
}

// NewLocalKey initializes a new local key
func NewLocalKey(keyPath string) (*Client, error) {
	if keyPath == "" {
		return &Client{}, errors.New("No encryption key path configured")
	}

	encKey, err := newEncryptionKey(keyPath)
	if err != nil {
		return &Client{}, err
	}

	return &Client{
		encryptionKey: encKey,
	}, nil

}

// InitBlock initializes the block cipher
func (l *Client) InitBlock(keyName string) error {
	key, err := l.encryptionKey.Key(keyName)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	l.cipher = block

	return nil
}

// GetEncryptedText localkey Client just returns the clearText
func (l *Client) GetEncryptedText(keyName, clearText string) (string, error) {
	secret := &internalSecret{
		Algorithm: "aes256-gcm",
	}

	err := l.InitBlock(keyName)
	if err != nil {
		return "", err
	}

	if l.cipher == nil {
		return "", errors.New("Cipher Block not initialized")
	}

	nonce, err := randomNonce(12)
	if err != nil {
		return "", err
	}

	secret.Nonce = nonce

	gcm, err := cipher.NewGCM(l.cipher)
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

// GetClearText localkey Client just returns the cipherText
func (l *Client) GetClearText(keyName, secretBlob string) (string, error) {
	secret := &internalSecret{}

	err := json.Unmarshal([]byte(secretBlob), secret)
	if err != nil {
		return "", err
	}

	err = l.InitBlock(keyName)
	if err != nil {
		return "", err
	}

	if l.cipher == nil {
		return "", errors.New("Cipher Block not initialized")
	}

	gcm, err := cipher.NewGCM(l.cipher)
	if err != nil {
		return "", err
	}

	plainText, err := gcm.Open(nil, secret.Nonce, secret.CipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

// Sign implements the interface
func (l *Client) Sign(keyName, clearText string) (string, error) {
	return "", nil
}

// VerifySignature implements the interface.
func (l *Client) VerifySignature(keyName, signature, message string) (bool, error) {
	return true, nil
}

func randomNonce(byteLength int) ([]byte, error) {
	key := make([]byte, byteLength)

	_, err := rand.Read(key)
	if err != nil {
		return []byte{}, err
	}

	return key, nil
}
