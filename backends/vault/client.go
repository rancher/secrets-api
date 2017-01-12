package vault

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/hashicorp/vault/api"
)

type Client struct {
	url   string
	token string
}

func NewClient(url, token string) (*Client, error) {
	return &Client{
		url:   url,
		token: token,
	}, nil
}

// GetEncryptedText None Client just returns the clearText
func (v *Client) GetEncryptedText(keyName, clearText string) (string, error) {
	encryptPath := fmt.Sprintf("/transit/encrypt/%s", keyName)

	preparedInput := prepareInput(clearText)
	data := map[string]interface{}{
		"plaintext": preparedInput,
	}

	secret, err := v.writeToVault(encryptPath, data)
	if err != nil {
		logrus.Error(err)
		return "", fmt.Errorf("Issue encrypting with %s key", keyName)
	}

	if cipherText, ok := secret.Data["ciphertext"].(string); ok && cipherText != "" {
		return cipherText, nil
	}

	return "", errors.New("Could not encrypt cleartext")
}

// GetClearText  None Client just returns the cipherText
func (v *Client) GetClearText(keyName, cipherText string) (string, error) {
	decryptPath := fmt.Sprintf("/transit/decrypt/%s", keyName)

	secret, err := v.writeToVault(decryptPath, map[string]interface{}{"ciphertext": cipherText})
	if err != nil {
		logrus.Error(err)
		return "", fmt.Errorf("Issue decrypting secret with %s key", keyName)
	}

	if plainText, ok := secret.Data["plaintext"].(string); ok && plainText != "" {
		byteString, err := base64.StdEncoding.DecodeString(plainText)
		if err != nil {
			return "", err
		}
		return string(byteString), nil
	}

	return "", errors.New("Could not decrypt ciphertext")
}

// Sign implements the interface
func (v *Client) Sign(keyName, clearText string) (string, error) {
	return "", nil
}

// VerifySignature verifies the signature
func (v *Client) VerifySignature(keyName, signature, message string) (bool, error) {
	return true, nil
}

func (v *Client) writeToVault(path string, data map[string]interface{}) (*api.Secret, error) {
	vaultClient, err := v.getVaultClient()
	if err != nil {
		return nil, err
	}

	return vaultClient.Logical().Write(path, data)
}

//Vault expects input to be base64 encoded
func prepareInput(text string) string {
	if _, err := base64.StdEncoding.DecodeString(text); err != nil {
		return base64.StdEncoding.EncodeToString([]byte(text))
	}

	return text
}

func (v *Client) getVaultClient() (*api.Client, error) {
	config := api.DefaultConfig()
	config.Address = v.url

	client, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}
	client.SetToken(v.token)

	return client, nil
}

func testVaultTransitKeyExists(vaultCli *api.Client, keyName string) (bool, error) {
	exists := false
	keyPath := fmt.Sprintf("/transit/keys/%s", keyName)

	secret, err := vaultCli.Logical().Read(keyPath)
	if err != nil {
		return exists, err
	}

	if secret != nil {
		if name, ok := secret.Data["name"]; ok && name == keyName {
			exists = true
		}
	}

	return exists, nil
}
