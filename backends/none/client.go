package none

import (
	"encoding/base64"
)

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
