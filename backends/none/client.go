package none

import (
	"encoding/base64"
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
	return "", nil
}

// VerifySignature verifies the signature created by the key
func (n *Client) VerifySignature(keyName, signature, message string) (bool, error) {
	return true, nil
}
