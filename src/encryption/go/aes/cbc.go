package aes

import "fmt"

// CBCEncrypt encrypts data using CBC mode
func CBCEncrypt(ctx *AESContext, data []byte) ([]byte, error) {
	// Generate random IV
	iv, err := GenerateRandomIV()
	if err != nil {
		return nil, err
	}

	// Add PKCS7 padding
	data = PKCS7Pad(data)

	// Prepend IV to ciphertext
	ciphertext := make([]byte, len(iv)+len(data))
	copy(ciphertext, iv)

	// Encrypt each block
	prev := iv
	for i := 0; i < len(data); i += AESBlockSize {
		block := ciphertext[len(iv)+i : len(iv)+i+AESBlockSize]
		copy(block, data[i:i+AESBlockSize])
		
		// XOR with previous ciphertext block
		for j := 0; j < AESBlockSize; j++ {
			block[j] ^= prev[j]
		}
		
		ctx.EncryptBlock(block)
		prev = block
	}

	return ciphertext, nil
}

// CBCDecrypt decrypts data using CBC mode
func CBCDecrypt(ctx *AESContext, data []byte) ([]byte, error) {
	if len(data) < AESBlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract IV
	iv := data[:AESBlockSize]
	data = data[AESBlockSize:]

	if len(data)%AESBlockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be multiple of block size")
	}

	// Decrypt each block
	plaintext := make([]byte, len(data))
	prev := iv
	for i := 0; i < len(data); i += AESBlockSize {
		block := plaintext[i : i+AESBlockSize]
		copy(block, data[i:i+AESBlockSize])
		
		// Save current ciphertext block
		current := make([]byte, AESBlockSize)
		copy(current, block)
		
		ctx.DecryptBlock(block)
		
		// XOR with previous ciphertext block
		for j := 0; j < AESBlockSize; j++ {
			block[j] ^= prev[j]
		}
		
		prev = current
	}

	// Remove PKCS7 padding
	return PKCS7Unpad(plaintext)
} 