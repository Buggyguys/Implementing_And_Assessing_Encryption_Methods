package aes

import (
	"fmt"
)

// ECBEncrypt encrypts data using ECB mode
func ECBEncrypt(ctx *AESContext, data []byte) ([]byte, error) {
	// Add PKCS7 padding
	data = PKCS7Pad(data)

	// Encrypt each block
	ciphertext := make([]byte, len(data))
	for i := 0; i < len(data); i += AESBlockSize {
		block := ciphertext[i : i+AESBlockSize]
		copy(block, data[i:i+AESBlockSize])
		ctx.EncryptBlock(block)
	}

	return ciphertext, nil
}

// ECBDecrypt decrypts data using ECB mode
func ECBDecrypt(ctx *AESContext, data []byte) ([]byte, error) {
	if len(data)%AESBlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be multiple of block size")
	}

	// Decrypt each block
	plaintext := make([]byte, len(data))
	for i := 0; i < len(data); i += AESBlockSize {
		block := plaintext[i : i+AESBlockSize]
		copy(block, data[i:i+AESBlockSize])
		ctx.DecryptBlock(block)
	}

	// Remove PKCS7 padding
	return PKCS7Unpad(plaintext)
} 