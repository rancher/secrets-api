package aesutils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"

	"github.com/Sirupsen/logrus"
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
	nonce := make([]byte, 12, 12)

	key, err := aesKey.Key()
	if err != nil {
		return false, err
	}

	byteSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}

	copy(nonce, byteSignature[:12])

	logrus.Debugf("Sent Signature in Bytes: %s", byteSignature)
	logrus.Debugf("Nonce: %s", nonce)
	logrus.Debugf("Sent Signed Cipher Text: %s", byteSignature[13:])

	signedMsg, err := sign(key, append(nonce, []byte(":"+message)...))
	if err != nil {
		return false, err
	}

	logrus.Debugf("Generated sig from deciphered text: %s", signedMsg)

	return hmac.Equal(byteSignature[13:], signedMsg), nil
}
