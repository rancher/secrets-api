package secrets

import (
	"github.com/rancher/secrets-api/pkg/aesutils"
	"github.com/rancher/secrets-api/pkg/rsautils"
)

func createMessageEnvelope(rsaKey, message string, tmpKey aesutils.AESKey) (*EncryptedData, error) {
	pubKey, err := rsautils.PublicKeyFromString(rsaKey)
	if err != nil {
		return nil, err
	}

	envelope := &EncryptedData{
		HashAlgorithm:       "",
		EncryptionAlgorithm: "aes256-gcm96",
	}

	if envelope.EncryptedText, err = aesutils.GetEncryptedText(tmpKey, message, "aes256-gcm"); err != nil {
		return envelope, err
	}

	if envelope.Signature, err = aesutils.Sign(tmpKey, envelope.EncryptedText); err != nil {
		return envelope, err
	}

	encryptedKey, err := rsaEncryptKey(pubKey, tmpKey)
	if err != nil {
		return envelope, err
	}

	envelope.EncryptedKey = *encryptedKey

	return envelope, nil
}
