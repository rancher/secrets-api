package none

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
)

//Client is the stuct implementing the backend client interface
type Client struct{}

// GetEncryptedText None Client just returns the clearText
func (n *Client) GetEncryptedText(keyName, clearText string) (string, error) {
	return base64.StdEncoding.EncodeToString([]byte(clearText)), nil
}

// GetClearText  None Client just returns the cipherText
func (n *Client) GetClearText(keyName, cipherText string) (string, error) {
	byteString, err := base64.StdEncoding.DecodeString(cipherText)
	return string(byteString), err
}

// Sign signs the message
func (n *Client) Sign(keyName, clearText string) (string, error) {
	hashBytes := md5.Sum([]byte(clearText))
	return hex.EncodeToString(hashBytes[:]), nil
}

// VerifySignature verifies the signature created by the key
func (n *Client) VerifySignature(keyName, signature, message string) (bool, error) {
	hashBytes := md5.Sum([]byte(message))
	return signature == hex.EncodeToString(hashBytes[:]), nil
}

// Delete No Op, not stored.
func (n *Client) Delete(keyName, cipherText string) error {
	return nil
}
