package aesutils

import "testing"

const secretText = "my secret to keep"

type testKey struct {
	key []byte
}

func (tk *testKey) Key() ([]byte, error) {
	return tk.key, nil
}

func TestLocalKeyClient(t *testing.T) {
	k, err := NewRandomAESKey(32)
	if err != nil {
		t.Error(err)
	}

	encdata, err := GetEncryptedText(k, secretText, "aes256-gcm")
	if err != nil {
		t.Error(err)
	}

	data, _ := GetClearText(k, encdata)
	if err != nil {
		t.Error(err)
	}

	if data != secretText {
		t.Errorf("Secret data decrypted to %s and we expected %s", data, secretText)
	}

}
