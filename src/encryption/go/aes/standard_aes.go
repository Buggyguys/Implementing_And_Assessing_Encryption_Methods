package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"encryption/utils"
)

// StandardAES implements the AESImplementation interface using Go's crypto/aes package
type StandardAES struct {
	block cipher.Block
	keySize int
	mode string
}

// Initialize sets up the implementation with the given key size and mode
func (s *StandardAES) Initialize(keySize int, mode string) error {
	key, err := utils.GenerateRandomBytes(keySize / 8)
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %v", err)
	}

	s.block = block
	s.keySize = keySize
	s.mode = mode
	return nil
}

// GenerateKey creates a new key of the specified size
func (s *StandardAES) GenerateKey() ([]byte, error) {
	return utils.GenerateRandomBytes(s.keySize / 8)
}

// Encrypt encrypts the plaintext using the specified mode
func (s *StandardAES) Encrypt(plaintext []byte, mode BlockMode, aad []byte) ([]byte, error) {
	// Pad the plaintext
	paddedPlaintext, err := utils.PadBlock(plaintext, s.block.BlockSize(), utils.PKCS7Padding)
	if err != nil {
		return nil, fmt.Errorf("padding error: %v", err)
	}

	// Initialize IV/nonce if needed
	var iv []byte
	if mode != ECB {
		var err error
		iv, err = utils.SecureRandomBytes(s.block.BlockSize())
		if err != nil {
			return nil, fmt.Errorf("failed to generate IV: %v", err)
		}
	}

	var ciphertext []byte
	switch mode {
	case ECB:
		ciphertext = make([]byte, len(paddedPlaintext))
		for i := 0; i < len(paddedPlaintext); i += s.block.BlockSize() {
			s.block.Encrypt(ciphertext[i:i+s.block.BlockSize()], paddedPlaintext[i:i+s.block.BlockSize()])
		}

	case CBC:
		ciphertext = make([]byte, len(paddedPlaintext)+s.block.BlockSize()) // Add space for IV
		copy(ciphertext, iv)
		
		encrypter := cipher.NewCBCEncrypter(s.block, iv)
		encrypter.CryptBlocks(ciphertext[s.block.BlockSize():], paddedPlaintext)

	case CTR:
		ciphertext = make([]byte, len(paddedPlaintext)+s.block.BlockSize()) // Add space for nonce
		copy(ciphertext, iv)
		
		stream := cipher.NewCTR(s.block, iv)
		stream.XORKeyStream(ciphertext[s.block.BlockSize():], paddedPlaintext)

	case GCM:
		aead, err := cipher.NewGCM(s.block)
		if err != nil {
			return nil, fmt.Errorf("failed to create GCM: %v", err)
		}

		ciphertext = aead.Seal(iv, iv, paddedPlaintext, aad)

	default:
		return nil, fmt.Errorf("unsupported mode of operation")
	}

	return ciphertext, nil
}

// Decrypt decrypts the ciphertext using the specified mode
func (s *StandardAES) Decrypt(ciphertext []byte, mode BlockMode, aad []byte) ([]byte, error) {
	if len(ciphertext) < s.block.BlockSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	var plaintext []byte
	var err error

	switch mode {
	case ECB:
		plaintext = make([]byte, len(ciphertext))
		for i := 0; i < len(ciphertext); i += s.block.BlockSize() {
			s.block.Decrypt(plaintext[i:i+s.block.BlockSize()], ciphertext[i:i+s.block.BlockSize()])
		}

	case CBC:
		if len(ciphertext) <= s.block.BlockSize() {
			return nil, fmt.Errorf("ciphertext too short for CBC mode")
		}

		iv := ciphertext[:s.block.BlockSize()]
		plaintext = make([]byte, len(ciphertext)-s.block.BlockSize())
		
		decrypter := cipher.NewCBCDecrypter(s.block, iv)
		decrypter.CryptBlocks(plaintext, ciphertext[s.block.BlockSize():])

	case CTR:
		if len(ciphertext) <= s.block.BlockSize() {
			return nil, fmt.Errorf("ciphertext too short for CTR mode")
		}

		nonce := ciphertext[:s.block.BlockSize()]
		plaintext = make([]byte, len(ciphertext)-s.block.BlockSize())
		
		stream := cipher.NewCTR(s.block, nonce)
		stream.XORKeyStream(plaintext, ciphertext[s.block.BlockSize():])

	case GCM:
		aead, err := cipher.NewGCM(s.block)
		if err != nil {
			return nil, fmt.Errorf("failed to create GCM: %v", err)
		}

		if len(ciphertext) < aead.NonceSize() {
			return nil, fmt.Errorf("ciphertext too short for GCM mode")
		}

		nonce := ciphertext[:aead.NonceSize()]
		plaintext, err = aead.Open(nil, nonce, ciphertext[aead.NonceSize():], aad)
		if err != nil {
			return nil, fmt.Errorf("authentication failed: %v", err)
		}

	default:
		return nil, fmt.Errorf("unsupported mode of operation")
	}

	// Unpad the plaintext (except for GCM which doesn't use padding)
	if mode != GCM {
		plaintext, err = utils.UnpadBlock(plaintext, s.block.BlockSize(), utils.PKCS7Padding)
		if err != nil {
			return nil, fmt.Errorf("unpadding error: %v", err)
		}
	}

	return plaintext, nil
}

// GetBlockSize returns the block size
func (s *StandardAES) GetBlockSize() int {
	return s.block.BlockSize()
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
