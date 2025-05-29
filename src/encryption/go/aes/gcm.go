package aes

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

// GCMEncrypt encrypts data using GCM mode
func GCMEncrypt(ctx *AESContext, data []byte) ([]byte, error) {
	// Generate random nonce (12 bytes for GCM)
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Initialize counter
	counter := make([]byte, AESBlockSize)
	copy(counter[len(counter)-len(nonce):], nonce)
	binary.BigEndian.PutUint32(counter[len(counter)-len(nonce)-4:], 1)

	// Generate GHASH key (H)
	h := make([]byte, AESBlockSize)
	ctx.EncryptBlock(h)

	// Encrypt data
	ciphertext := make([]byte, len(data))
	encCounter := make([]byte, AESBlockSize)
	copy(encCounter, counter)
	ctx.EncryptBlock(encCounter)

	for i := 0; i < len(data); i += AESBlockSize {
		// Increment counter
		for j := len(counter) - 1; j >= 0; j-- {
			counter[j]++
			if counter[j] != 0 {
				break
			}
		}

		// Encrypt counter
		copy(encCounter, counter)
		ctx.EncryptBlock(encCounter)

		// XOR with plaintext
		remaining := len(data) - i
		if remaining > AESBlockSize {
			remaining = AESBlockSize
		}

		for j := 0; j < remaining; j++ {
			ciphertext[i+j] = data[i+j] ^ encCounter[j]
		}
	}

	// Calculate authentication tag
	tag := calculateGCMTag(ctx, h, nonce, ciphertext, nil)

	// Combine nonce, ciphertext, and tag
	result := make([]byte, len(nonce)+len(ciphertext)+len(tag))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)
	copy(result[len(nonce)+len(ciphertext):], tag)

	return result, nil
}

// GCMDecrypt decrypts data using GCM mode
func GCMDecrypt(ctx *AESContext, data []byte) ([]byte, error) {
	if len(data) < 12+16 { // Nonce + Tag
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and tag
	nonce := data[:12]
	tag := data[len(data)-16:]
	ciphertext := data[12 : len(data)-16]

	// Initialize counter
	counter := make([]byte, AESBlockSize)
	copy(counter[len(counter)-len(nonce):], nonce)
	binary.BigEndian.PutUint32(counter[len(counter)-len(nonce)-4:], 1)

	// Generate GHASH key (H)
	h := make([]byte, AESBlockSize)
	ctx.EncryptBlock(h)

	// Verify tag
	expectedTag := calculateGCMTag(ctx, h, nonce, ciphertext, nil)
	if !hmac.Equal(tag, expectedTag) {
		return nil, fmt.Errorf("authentication failed")
	}

	// Decrypt data
	plaintext := make([]byte, len(ciphertext))
	encCounter := make([]byte, AESBlockSize)
	copy(encCounter, counter)
	ctx.EncryptBlock(encCounter)

	for i := 0; i < len(ciphertext); i += AESBlockSize {
		// Increment counter
		for j := len(counter) - 1; j >= 0; j-- {
			counter[j]++
			if counter[j] != 0 {
				break
			}
		}

		// Encrypt counter
		copy(encCounter, counter)
		ctx.EncryptBlock(encCounter)

		// XOR with ciphertext
		remaining := len(ciphertext) - i
		if remaining > AESBlockSize {
			remaining = AESBlockSize
		}

		for j := 0; j < remaining; j++ {
			plaintext[i+j] = ciphertext[i+j] ^ encCounter[j]
		}
	}

	return plaintext, nil
}

// Helper function for GCM tag calculation
func calculateGCMTag(ctx *AESContext, h, nonce, ciphertext, aad []byte) []byte {
	// Calculate GHASH
	ghash := calculateGHASH(h, ciphertext, aad)

	// Generate initial counter block
	counter := make([]byte, AESBlockSize)
	copy(counter[len(counter)-len(nonce):], nonce)

	// Encrypt counter block
	ctx.EncryptBlock(counter)

	// XOR GHASH with encrypted counter
	tag := make([]byte, AESBlockSize)
	for i := 0; i < AESBlockSize; i++ {
		tag[i] = ghash[i] ^ counter[i]
	}

	return tag
}

// Helper function for GHASH calculation
func calculateGHASH(h []byte, ciphertext, aad []byte) []byte {
	// Initialize hash
	hash := make([]byte, AESBlockSize)

	// Process AAD
	if len(aad) > 0 {
		for i := 0; i < len(aad); i += AESBlockSize {
			block := make([]byte, AESBlockSize)
			remaining := len(aad) - i
			if remaining > AESBlockSize {
				remaining = AESBlockSize
			}
			copy(block, aad[i:i+remaining])
			ghashBlock(hash, block, h)
		}
	}

	// Process ciphertext
	for i := 0; i < len(ciphertext); i += AESBlockSize {
		block := make([]byte, AESBlockSize)
		remaining := len(ciphertext) - i
		if remaining > AESBlockSize {
			remaining = AESBlockSize
		}
		copy(block, ciphertext[i:i+remaining])
		ghashBlock(hash, block, h)
	}

	// Process lengths
	block := make([]byte, AESBlockSize)
	binary.BigEndian.PutUint64(block[:8], uint64(len(aad))*8)
	binary.BigEndian.PutUint64(block[8:], uint64(len(ciphertext))*8)
	ghashBlock(hash, block, h)

	return hash
}

// Helper function for GHASH block processing
func ghashBlock(hash, block, h []byte) {
	// XOR hash with block
	for i := 0; i < AESBlockSize; i++ {
		hash[i] ^= block[i]
	}

	// Multiply by H in GF(2^128)
	gfMultiply(hash, h)
}

// Helper function for GF(2^128) multiplication
func gfMultiply(x, y []byte) {
	r := make([]byte, AESBlockSize)
	for i := 0; i < AESBlockSize; i++ {
		for j := 7; j >= 0; j-- {
			if x[i]&(1<<uint(j)) != 0 {
				for k := 0; k < AESBlockSize; k++ {
					r[k] ^= y[k]
				}
			}
			// Right shift y
			carry := false
			for k := AESBlockSize - 1; k >= 0; k-- {
				newCarry := y[k]&1 != 0
				y[k] >>= 1
				if carry {
					y[k] |= 0x80
				}
				carry = newCarry
			}
			if carry {
				y[AESBlockSize-1] ^= 0xe1
			}
		}
	}
	copy(x, r)
} 