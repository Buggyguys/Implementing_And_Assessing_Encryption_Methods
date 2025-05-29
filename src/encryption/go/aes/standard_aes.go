package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// StandardAES implements the AESImplementation interface using Go's crypto/aes package
type StandardAES struct {
	keySize    int    // Key size in bits (128, 192, or 256)
	mode       string // Mode of operation (ECB, CBC, CTR, GCM)
	blockSize  int    // Block size in bytes (16 for AES)
	ivSize     int    // IV size in bytes (16 for AES)
	numRounds  int    // Number of rounds (10 for AES-128, 12 for AES-192, 14 for AES-256)
}

// Initialize sets up the implementation with the given key size and mode
func (s *StandardAES) Initialize(keySize int, mode string) error {
	// Validate key size
	switch keySize {
	case 128:
		s.keySize = keySize
		s.numRounds = 10
	case 192:
		s.keySize = keySize
		s.numRounds = 12
	case 256:
		s.keySize = keySize
		s.numRounds = 14
	default:
		return fmt.Errorf("invalid key size: %d (must be 128, 192, or 256)", keySize)
	}

	// Set block size and IV size (constant for AES)
	s.blockSize = 16 // AES always uses 16-byte blocks
	s.ivSize = 16    // AES modes use 16-byte IV/nonce

	// Validate mode
	switch mode {
	case "ECB", "CBC", "CTR", "GCM":
		s.mode = mode
	default:
		return fmt.Errorf("invalid mode: %s (must be ECB, CBC, CTR, or GCM)", mode)
	}

	return nil
}

// GenerateKey creates a new key of the specified size
func (s *StandardAES) GenerateKey() ([]byte, error) {
	key := make([]byte, s.keySize/8)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt encrypts the given data using the specified key and mode
func (s *StandardAES) Encrypt(key []byte, data []byte) ([]byte, error) {
	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	switch s.mode {
	case "ECB":
		return s.encryptECB(block, data)
	case "CBC":
		return s.encryptCBC(block, data)
	case "CTR":
		return s.encryptCTR(block, data)
	case "GCM":
		return s.encryptGCM(block, data)
	default:
		return nil, fmt.Errorf("unsupported mode: %s", s.mode)
	}
}

// Decrypt decrypts the given data using the specified key and mode
func (s *StandardAES) Decrypt(key []byte, data []byte) ([]byte, error) {
	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	switch s.mode {
	case "ECB":
		return s.decryptECB(block, data)
	case "CBC":
		return s.decryptCBC(block, data)
	case "CTR":
		return s.decryptCTR(block, data)
	case "GCM":
		return s.decryptGCM(block, data)
	default:
		return nil, fmt.Errorf("unsupported mode: %s", s.mode)
	}
}

// GetName returns the name of the implementation
func (s *StandardAES) GetName() string {
	return "Standard AES"
}

// GetKeySize returns the current key size in bits
func (s *StandardAES) GetKeySize() int {
	return s.keySize
}

// GetMode returns the current mode of operation
func (s *StandardAES) GetMode() string {
	return s.mode
}

// IsCustomImplementation returns whether this is a custom implementation
func (s *StandardAES) IsCustomImplementation() bool {
	return false
}

// GetBlockSize returns the block size in bytes
func (s *StandardAES) GetBlockSize() int {
	return s.blockSize
}

// GetIVSize returns the IV size in bytes
func (s *StandardAES) GetIVSize() int {
	return s.ivSize
}

// GetNumRounds returns the number of rounds
func (s *StandardAES) GetNumRounds() int {
	return s.numRounds
}

// ECB mode implementation
func (s *StandardAES) encryptECB(block cipher.Block, data []byte) ([]byte, error) {
	// Add PKCS7 padding
	blockSize := block.BlockSize()
	data = pkcs7Pad(data, blockSize)

	// Encrypt each block
	ciphertext := make([]byte, len(data))
	for i := 0; i < len(data); i += blockSize {
		block.Encrypt(ciphertext[i:i+blockSize], data[i:i+blockSize])
	}

	return ciphertext, nil
}

func (s *StandardAES) decryptECB(block cipher.Block, data []byte) ([]byte, error) {
	blockSize := block.BlockSize()
	if len(data)%blockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}

	plaintext := make([]byte, len(data))
	for i := 0; i < len(data); i += blockSize {
		block.Decrypt(plaintext[i:i+blockSize], data[i:i+blockSize])
	}

	// Remove PKCS7 padding
	return pkcs7Unpad(plaintext)
}

// CBC mode implementation
func (s *StandardAES) encryptCBC(block cipher.Block, data []byte) ([]byte, error) {
	// Generate random IV
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Add PKCS7 padding
	data = pkcs7Pad(data, block.BlockSize())

	// Create CBC encrypter
	ciphertext := make([]byte, len(data)+len(iv))
	copy(ciphertext[:len(iv)], iv)
	
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[len(iv):], data)

	return ciphertext, nil
}

func (s *StandardAES) decryptCBC(block cipher.Block, data []byte) ([]byte, error) {
	if len(data) < block.BlockSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract IV
	iv := data[:block.BlockSize()]
	data = data[block.BlockSize():]

	if len(data)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}

	// Create CBC decrypter
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(data))
	mode.CryptBlocks(plaintext, data)

	// Remove PKCS7 padding
	return pkcs7Unpad(plaintext)
}

// CTR mode implementation
func (s *StandardAES) encryptCTR(block cipher.Block, data []byte) ([]byte, error) {
	// Generate random nonce
	nonce := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Create CTR stream
	ciphertext := make([]byte, len(data)+len(nonce))
	copy(ciphertext[:len(nonce)], nonce)
	
	stream := cipher.NewCTR(block, nonce)
	stream.XORKeyStream(ciphertext[len(nonce):], data)

	return ciphertext, nil
}

func (s *StandardAES) decryptCTR(block cipher.Block, data []byte) ([]byte, error) {
	if len(data) < block.BlockSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce
	nonce := data[:block.BlockSize()]
	data = data[block.BlockSize():]

	// Create CTR stream
	plaintext := make([]byte, len(data))
	stream := cipher.NewCTR(block, nonce)
	stream.XORKeyStream(plaintext, data)

	return plaintext, nil
}

// GCM mode implementation
func (s *StandardAES) encryptGCM(block cipher.Block, data []byte) ([]byte, error) {
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate random nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and append nonce
	ciphertext := aead.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (s *StandardAES) decryptGCM(block cipher.Block, data []byte) ([]byte, error) {
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce := data[:aead.NonceSize()]
	ciphertext := data[aead.NonceSize():]

	// Decrypt
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// PKCS7 padding helpers
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("empty data")
	}
	
	padding := int(data[length-1])
	if padding > length {
		return nil, fmt.Errorf("invalid padding size")
	}

	// Verify padding
	for i := length - padding; i < length; i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:length-padding], nil
}
