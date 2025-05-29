package aes

import (
	"crypto/rand"
	"encoding/binary"
	"io"
)

// CTREncrypt encrypts data using CTR mode
func CTREncrypt(ctx *AESContext, data []byte) ([]byte, error) {
	// Generate random nonce
	nonce := make([]byte, AESBlockSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Prepend nonce to ciphertext
	ciphertext := make([]byte, len(nonce)+len(data))
	copy(ciphertext, nonce)

	// Encrypt each block
	counter := make([]byte, AESBlockSize)
	for i := 0; i < len(data); i += AESBlockSize {
		// Copy nonce to counter block
		copy(counter, nonce)
		
		// Add block counter to last 4 bytes
		binary.BigEndian.PutUint32(counter[12:], uint32(i/AESBlockSize))
		
		// Encrypt counter
		ctx.EncryptBlock(counter)
		
		// XOR with plaintext
		remaining := len(data) - i
		if remaining > AESBlockSize {
			remaining = AESBlockSize
		}
		
		for j := 0; j < remaining; j++ {
			ciphertext[len(nonce)+i+j] = data[i+j] ^ counter[j]
		}
	}

	return ciphertext, nil
}

// CTRDecrypt decrypts data using CTR mode
func CTRDecrypt(ctx *AESContext, data []byte) ([]byte, error) {
	// CTR mode decryption is identical to encryption
	return CTREncrypt(ctx, data)
} 