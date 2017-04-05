package aesutils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// Sign implements the interface
func Sign(aesKey AESKey, clearText string) (string, error) {
	key, err := aesKey.Key()
	if err != nil {
		return "", err
	}

	IV, err := randomNonce(12)
	if err != nil {
		return "", err
	}

	// Add a nonce so that we do not get collisions for the same input
	signedMsg, err := sign(key, append(IV, []byte(":"+clearText)...))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(append(IV, []byte(":"+string(signedMsg))...)), nil
}

func sign(key, msg []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)

	return mac.Sum(nil), nil
}

// VerifySignature implements the interface.
func VerifySignature(aesKey AESKey, signature, message string) (bool, error) {
	key, err := aesKey.Key()
	if err != nil {
		return false, err
	}

	byteSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	signedMsg, err := sign(key, append(byteSignature[:12], []byte(":"+message)...))
	if err != nil {
		return false, err
	}

	return hmac.Equal(byteSignature[13:], signedMsg), nil
}
