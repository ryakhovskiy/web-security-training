package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

type EncryptedPayload struct {
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, err
	}

	nonce := make([]byte, 12)
	_, err = rand.Read(nonce)
	if nil != err {
		return EncryptedPayload{}, err
	}

	sealedPayload := aesGCM.Seal(nil, nonce, plaintext, nil)
	tagSize := aesGCM.Overhead()
	splitIndex := len(sealedPayload) - tagSize
	ciphertext := sealedPayload[:splitIndex]
	tag := sealedPayload[splitIndex:]

	return EncryptedPayload{
		Nonce:      nonce,
		AuthTag:    tag,
		Ciphertext: ciphertext,
	}, nil
}

func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	if payload.AuthTag == nil || len(payload.AuthTag) != 16 || payload.Nonce == nil || len(payload.Nonce) != 12 {
		return nil, fmt.Errorf("Invalid Encrypted Payload")
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	combinedPayload := make([]byte, 0, len(payload.Ciphertext)+len(payload.AuthTag))
	combinedPayload = append(combinedPayload, payload.Ciphertext...)
	combinedPayload = append(combinedPayload, payload.AuthTag...)
	plaintext, err := aesGCM.Open(nil, payload.Nonce, combinedPayload, nil)
	if nil != err {
		return nil, err
	}
	return plaintext, nil
}
