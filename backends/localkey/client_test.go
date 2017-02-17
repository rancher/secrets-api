package localkey

import (
	"encoding/json"
	"testing"

	"github.com/rancher/secrets-api/pkg/aesutils"
)

const secretText = "my secret to keep"

type testKey struct {
	key []byte
}

func (tk *testKey) Key(keyName string) ([]byte, error) {
	return tk.key, nil
}

func TestLocalKeyClient(t *testing.T) {
	// Give it a real directory... but we are going to override the key
	client, err := NewLocalKey("./")
	if err != nil {
		t.Error(err)
	}

	t.Skip("Need a way to inject key")
	_, err = aesutils.NewRandomAESKey(32)
	if err != nil {
		t.Error(err)
	}

	//client.encryptionKey = key

	encdata, err := client.GetEncryptedText("testing", secretText)
	if err != nil {
		t.Error(err)
	}

	data, _ := client.GetClearText("testing", encdata)
	if err != nil {
		t.Error(err)
	}

	if data != secretText {
		t.Errorf("Secret data decrypted to '%s' and we expected '%s'", data, secretText)
	}

}

func TestConvertNonceToIV(t *testing.T) {
	s1 := &internalSecret{
		Nonce:      []byte("NONCE"),
		Algorithm:  "aes256-gcm",
		CipherText: []byte("CIPHER"),
	}

	expected := &internalSecret{
		IV:         []byte("NONCE"),
		Algorithm:  "aes256-gcm",
		CipherText: []byte("CIPHER"),
	}

	expectedBytes, err := json.Marshal(expected)
	if err != nil {
		t.Error(err)
	}

	byteS1, err := json.Marshal(s1)
	if err != nil {
		t.Error(err)
	}

	cleaned, err := convertNonceToIV(string(byteS1))
	if err != nil {
		t.Error(err)
	}

	if cleaned != string(expectedBytes) {
		t.Errorf("Cleaned: %#v not equal expected %#v", cleaned, expectedBytes)
	}

}
