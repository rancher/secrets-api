package vault

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"encoding/base64"

	"github.com/Sirupsen/logrus"
	"github.com/hashicorp/vault/api"
)

var client *Client

// Client is the struct that implements the backend interface
type Client struct {
	url         string
	token       string
	storageDir  string
	vaultClient *api.Client
}

// NewClient returns a Client type that is ready to interact
// with vault
func NewClient(url, token string) (*Client, error) {
	var err error
	if client != nil {
		return client, err
	}

	c := &Client{
		url:   url,
		token: token,
	}

	c.storageDir, err = c.getStorageDir()
	if err != nil {
		return client, err
	}

	err = c.initVaultClient()
	if err != nil {
		return nil, err
	}

	return client, nil
}

// GetEncryptedText None Client just returns the clearText
func (v *Client) GetEncryptedText(keyName, clearText string) (string, error) {
	encryptPath := fmt.Sprintf("/transit/encrypt/%s", keyName)

	data := map[string]interface{}{
		"plaintext": clearText,
	}

	secret, err := v.writeToVault(encryptPath, data)
	if err != nil {
		logrus.Error(err)
		return "", fmt.Errorf("Issue encrypting with %s key", keyName)
	}

	if cipherText, ok := secret.Data["ciphertext"].(string); ok && cipherText != "" {
		if v.storageDir != "" {
			cipherText, err = v.storeSecretInVault(cipherText)
			if err != nil {
				return "", err
			}
		}
		return cipherText, nil
	}

	return "", errors.New("Could not encrypt cleartext")
}

// GetClearText  None Client just returns the cipherText
func (v *Client) GetClearText(keyName, cipherText string) (string, error) {
	var err error
	decryptPath := fmt.Sprintf("/transit/decrypt/%s", keyName)

	if v.storageDir != "" {
		cipherText, err = v.retrieveSecretFromVault(cipherText)
		if err != nil {
			return "", err
		}
	}

	secret, err := v.writeToVault(decryptPath, map[string]interface{}{"ciphertext": cipherText})
	if err != nil {
		logrus.Error(err)
		return "", fmt.Errorf("Issue decrypting secret with %s key", keyName)
	}

	if plainText, ok := secret.Data["plaintext"].(string); ok && plainText != "" {
		return plainText, nil
	}

	return "", errors.New("Could not decrypt ciphertext")
}

// Sign implements the interface
func (v *Client) Sign(keyName, clearText string) (string, error) {
	hmacPath := fmt.Sprintf("/transit/hmac/%s", keyName)
	data := map[string]interface{}{
		"algorithm": "sha2-256",
	}

	nonceResp, err := v.writeToVault("/transit/random/8", map[string]interface{}{})
	if err != nil {
		return "", err
	}

	nonce, ok := nonceResp.Data["random_bytes"].(string)
	if !ok || nonce == "" {
		return "", errors.New("Could not generate nonce")
	}

	data["input"], _ = formatSignatureString(nonce, clearText)

	secret, err := v.writeToVault(hmacPath, data)
	if err != nil {
		return "", err
	}

	if signature, ok := secret.Data["hmac"].(string); ok && signature != "" {
		return nonce + ":" + signature, nil
	}

	return "", errors.New("Could not get a signature")
}

// VerifySignature verifies the signature
func (v *Client) VerifySignature(keyName, signature, message string) (bool, error) {
	comparePath := fmt.Sprintf("/transit/verify/%s/sha2-256", keyName)
	logrus.Debugf("Vault Backend: verify signature: %s against key %s", signature, keyName)

	sigSplit := strings.SplitN(signature, ":", 2)
	if len(sigSplit) != 2 {
		return false, errors.New("Invalid signature format")
	}

	nonce := sigSplit[0]

	data := map[string]interface{}{
		"hmac": sigSplit[1],
	}

	data["input"], _ = formatSignatureString(nonce, message)

	secret, err := v.writeToVault(comparePath, data)
	if err != nil {
		return false, err
	}

	verified, ok := secret.Data["valid"].(bool)
	if verified && ok {
		return true, nil
	}
	return false, nil
}

func (v *Client) Delete(keyName, cipherText string) error {

	if v.storageDir != "" {
		_, err := v.vaultClient.Logical().Delete(cipherText)
		if err != nil {
			return err
		}
	}

	return nil
}

func (v *Client) writeToVault(path string, data map[string]interface{}) (*api.Secret, error) {
	return v.vaultClient.Logical().Write(path, data)
}

func (v *Client) getStorageDir() (string, error) {
	tokenLookupData := map[string]interface{}{
		"token": v.token,
	}

	secret, err := v.writeToVault("/auth/token/lookup", tokenLookupData)
	if err != nil {
		return "", err
	}

	if meta, ok := secret.Data["meta"].(map[string]interface{}); ok {
		if storageDir, ok := meta["storage_dir"]; ok {
			return storageDir.(string), nil
		}
	}

	return "", nil
}

// GetVaultClient returns a vault api client
func (v *Client) initVaultClient() error {
	config := api.DefaultConfig()
	config.Address = v.url

	client, err := api.NewClient(config)
	if err != nil {
		return err
	}
	client.SetToken(v.token)
	secret, err := client.Auth().Token().LookupSelf()
	if err != nil {
		return err
	}
	if !isRenewable(secret) {
		return fmt.Errorf("vault token is non renewable")
	}
	v.RenewLease()
	v.vaultClient = client

	return nil
}

func isRenewable(secret *api.Secret) bool {
	if secret != nil {
		data := secret.Data
		if value, ok := data["renewable"]; ok {
			if value == true {
				return true
			}
		}
	}

	return false
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

func formatSignatureString(nonce, data string) (string, error) {
	return base64.StdEncoding.EncodeToString([]byte(nonce + ":" + data)), nil
}

func (v *Client) storeSecretInVault(cipherText string) (string, error) {
	// write secret to path in Vault
	hash := sha256.New()
	hash.Write([]byte(cipherText))

	path := fmt.Sprintf("%s/v1-secrets/%x", v.storageDir, string(hash.Sum(nil)))

	_, err := v.writeToVault(path, map[string]interface{}{
		"cipherText": cipherText,
	})
	if err != nil {
		return "", err
	}

	// we will just pass back the location
	return path, nil
}

func (v *Client) retrieveSecretFromVault(path string) (string, error) {

	secret, err := v.vaultClient.Logical().Read(path)
	if err != nil {
		return "", err
	}

	logrus.Debugf("%#v", secret)
	if text, ok := secret.Data["cipherText"]; ok {
		return text.(string), nil
	}

	return "", fmt.Errorf("No CipherText at this location")
}
