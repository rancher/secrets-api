package localkey

import "testing"

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

	key, err := randomNonce(32)
	if err != nil {
		t.Error(err)
	}

	client.encryptionKey = &testKey{key: key}
	client.InitBlock("testKey")

	encdata, err := client.GetEncryptedText("testing", secretText)
	if err != nil {
		t.Error(err)
	}

	data, _ := client.GetClearText("testing", encdata)
	if err != nil {
		t.Error(err)
	}

	if data != secretText {
		t.Errorf("Secret data decrypted to %s and we expected %s", data, secretText)
	}

}
