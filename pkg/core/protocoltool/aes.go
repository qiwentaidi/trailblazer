package protocoltool

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func DecryptAESCBCHex(cipherHex, keyHex, ivHex string) (string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("invalid aes key hex: %w", err)
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", fmt.Errorf("invalid aes key length")
	}

	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return "", fmt.Errorf("invalid aes iv hex: %w", err)
	}
	if len(iv) != aes.BlockSize {
		return "", fmt.Errorf("invalid aes iv length")
	}

	cipherBytes, err := hex.DecodeString(cipherHex)
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext hex: %w", err)
	}
	if len(cipherBytes) == 0 || len(cipherBytes)%aes.BlockSize != 0 {
		return "", fmt.Errorf("invalid ciphertext length")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plaintextBytes := make([]byte, len(cipherBytes))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintextBytes, cipherBytes)
	plaintextBytes, err = pkcs7Unpad(plaintextBytes, aes.BlockSize)
	if err != nil {
		return "", err
	}

	return string(plaintextBytes), nil
}

func DecryptAESGCM(ciphertextMaterial, keyMaterial, ivMaterial, aadMaterial string) (string, error) {
	key, err := decodeFlexibleBytes(keyMaterial)
	if err != nil {
		return "", fmt.Errorf("invalid aes-gcm key: %w", err)
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", fmt.Errorf("invalid aes-gcm key length")
	}

	nonce, err := decodeFlexibleBytes(ivMaterial)
	if err != nil {
		return "", fmt.Errorf("invalid aes-gcm iv: %w", err)
	}
	if len(nonce) == 0 {
		return "", fmt.Errorf("missing aes-gcm iv")
	}

	cipherBytes, err := decodeFlexibleBytes(ciphertextMaterial)
	if err != nil {
		return "", fmt.Errorf("invalid aes-gcm ciphertext: %w", err)
	}
	if len(cipherBytes) == 0 {
		return "", fmt.Errorf("missing aes-gcm ciphertext")
	}

	additionalData := []byte(nil)
	if aadMaterial != "" {
		additionalData, err = decodeFlexibleBytes(aadMaterial)
		if err != nil {
			return "", fmt.Errorf("invalid aes-gcm additional data: %w", err)
		}
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	var gcm cipher.AEAD
	if len(nonce) == 12 {
		gcm, err = cipher.NewGCM(block)
	} else {
		gcm, err = cipher.NewGCMWithNonceSize(block, len(nonce))
	}
	if err != nil {
		return "", err
	}

	plaintextBytes, err := gcm.Open(nil, nonce, cipherBytes, additionalData)
	if err != nil {
		return "", err
	}
	return string(plaintextBytes), nil
}

func EncryptAESGCMBase64(plaintext string, key, nonce, additionalData []byte) (string, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return "", fmt.Errorf("invalid aes-gcm key length")
	}
	if len(nonce) == 0 {
		return "", fmt.Errorf("missing aes-gcm nonce")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	var gcm cipher.AEAD
	if len(nonce) == 12 {
		gcm, err = cipher.NewGCM(block)
	} else {
		gcm, err = cipher.NewGCMWithNonceSize(block, len(nonce))
	}
	if err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), additionalData)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decodeFlexibleBytes(value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("empty value")
	}

	if isHexCandidate(value) {
		decoded, err := hex.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
	}

	if isBase64Candidate(value) {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
		decoded, err = base64.RawStdEncoding.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
	}

	return []byte(value), nil
}

func isHexCandidate(value string) bool {
	if len(value) < 2 || len(value)%2 != 0 {
		return false
	}
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') && (ch < 'A' || ch > 'F') {
			return false
		}
	}
	return true
}

func isBase64Candidate(value string) bool {
	if len(value) < 8 || len(value)%4 != 0 {
		return false
	}
	for _, ch := range value {
		switch {
		case ch >= 'A' && ch <= 'Z':
		case ch >= 'a' && ch <= 'z':
		case ch >= '0' && ch <= '9':
		case ch == '+' || ch == '/' || ch == '=' || ch == '-' || ch == '_':
		default:
			return false
		}
	}
	return true
}
