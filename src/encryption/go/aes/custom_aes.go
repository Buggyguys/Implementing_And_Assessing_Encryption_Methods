package aes

import (
	"fmt"
	"encryption/utils"
	"encoding/binary"
	"sync"
)

// Buffer pools for frequently allocated sizes
var (
	blockBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, AESBlockSize)
		},
	}
	
	// Pool for larger buffers used in encryption/decryption
	largeBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024) // 32KB default size
		},
	}
)

// getBuffer gets a buffer of at least the requested size
func getBuffer(size int) []byte {
	if size <= AESBlockSize {
		return blockBufferPool.Get().([]byte)[:size]
	}
	
	buf := largeBufferPool.Get().([]byte)
	if cap(buf) < size {
		// If buffer is too small, allocate a new one
		buf = make([]byte, size)
	}
	return buf[:size]
}

// putBuffer returns a buffer to the appropriate pool
func putBuffer(buf []byte) {
	if cap(buf) <= AESBlockSize {
		blockBufferPool.Put(buf)
	} else {
		largeBufferPool.Put(buf)
	}
}

// CustomAES implements the AESImplementation interface with a custom implementation
type CustomAES struct {
	ctx *AESContext
}

// NewCustomAES creates a new instance of CustomAES with the given key
func NewCustomAES(key []byte) (*CustomAES, error) {
	ctx, err := NewAESContext(key)
	if err != nil {
		return nil, err
	}
	return &CustomAES{ctx: ctx}, nil
}

// Initialize sets up the implementation with the given key size and mode
func (c *CustomAES) Initialize(keySize int, mode string) error {
	key, err := utils.GenerateRandomBytes(keySize / 8)
	if err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	ctx, err := NewAESContext(key)
	if err != nil {
		return fmt.Errorf("failed to create AES context: %v", err)
	}

	ctx.KeySize = keySize
	ctx.Mode = mode
	c.ctx = ctx
	return nil
}

// GenerateKey creates a new key of the specified size
func (c *CustomAES) GenerateKey() ([]byte, error) {
	return utils.GenerateRandomBytes(c.ctx.KeySize / 8)
}

// Encrypt encrypts the plaintext using the specified mode of operation
func (c *CustomAES) Encrypt(plaintext []byte, mode BlockMode, aad []byte) ([]byte, error) {
	// Pad the plaintext
	paddedPlaintext, err := utils.PadBlock(plaintext, AESBlockSize, utils.PKCS7Padding)
	if err != nil {
		return nil, fmt.Errorf("padding error: %v", err)
	}

	// Get IV/nonce from pool if needed
	var iv []byte
	if mode != ECB {
		iv = getBuffer(AESBlockSize)
		defer putBuffer(iv)
		if _, err := utils.SecureRandomBytesInto(iv); err != nil {
			return nil, fmt.Errorf("failed to generate IV: %v", err)
		}
	}

	// Create mode-specific encrypter
	blockEncrypter := func(block []byte) {
		c.ctx.EncryptBlock(block)
	}

	var ciphertext []byte
	switch mode {
	case ECB:
		ciphertext = getBuffer(len(paddedPlaintext))
		copy(ciphertext, paddedPlaintext)
		for i := 0; i < len(ciphertext); i += AESBlockSize {
			blockEncrypter(ciphertext[i : i+AESBlockSize])
		}

	case CBC:
		ciphertext = getBuffer(len(paddedPlaintext) + AESBlockSize)
		copy(ciphertext, iv)
		copy(ciphertext[AESBlockSize:], paddedPlaintext)
		
		prevBlock := ciphertext[:AESBlockSize]
		for i := AESBlockSize; i < len(ciphertext); i += AESBlockSize {
			block := ciphertext[i : i+AESBlockSize]
			utils.XORBytes(block, prevBlock)
			blockEncrypter(block)
			prevBlock = block
		}

	case CTR:
		counter := getBuffer(AESBlockSize)
		defer putBuffer(counter)
		copy(counter, iv)

		ciphertext = getBuffer(len(paddedPlaintext) + AESBlockSize)
		copy(ciphertext, iv)
		
		keystream := getBuffer(AESBlockSize)
		defer putBuffer(keystream)
		
		for i := 0; i < len(paddedPlaintext); i += AESBlockSize {
			copy(keystream, counter)
			blockEncrypter(keystream)
			
			end := i + AESBlockSize
			if end > len(paddedPlaintext) {
				end = len(paddedPlaintext)
			}
			
			for j := 0; j < end-i; j++ {
				ciphertext[AESBlockSize+i+j] = paddedPlaintext[i+j] ^ keystream[j]
			}
			
			utils.IncrementCounter(counter)
		}

	case GCM:
		if len(iv) != 12 {
			// For non-96-bit IVs, GHASH the IV
			h := getBuffer(AESBlockSize)
			defer putBuffer(h)
			blockEncrypter(h) // H = E(K, 0^128)
			
			ghash := getBuffer(AESBlockSize)
			defer putBuffer(ghash)
			
			ivBlocks := (len(iv) + AESBlockSize - 1) / AESBlockSize
			for i := 0; i < ivBlocks; i++ {
				start := i * AESBlockSize
				end := start + AESBlockSize
				if end > len(iv) {
					end = len(iv)
				}
				block := getBuffer(AESBlockSize)
				copy(block, iv[start:end])
				utils.XORBytes(ghash, block)
				ghash = utils.GaloisFieldMultiply(ghash, h)
				putBuffer(block)
			}
			
			lengths := getBuffer(16)
			binary.BigEndian.PutUint64(lengths[8:], uint64(len(iv)*8))
			utils.XORBytes(ghash, lengths)
			ghash = utils.GaloisFieldMultiply(ghash, h)
			putBuffer(lengths)
			
			// Update IV to use GHASH result
			iv = getBuffer(AESBlockSize)
			copy(iv, ghash)
		}

		// Format counter block
		counter := getBuffer(AESBlockSize)
		defer putBuffer(counter)
		copy(counter[:12], iv)
		counter[15] = 1

		ciphertext = getBuffer(len(paddedPlaintext) + AESBlockSize + 16)
		copy(ciphertext, iv)
		
		keystream := getBuffer(AESBlockSize)
		defer putBuffer(keystream)
		
		// Encrypt using CTR mode
		for i := 0; i < len(paddedPlaintext); i += AESBlockSize {
			copy(keystream, counter)
			blockEncrypter(keystream)
			
			end := i + AESBlockSize
			if end > len(paddedPlaintext) {
				end = len(paddedPlaintext)
			}
			
			for j := 0; j < end-i; j++ {
				ciphertext[AESBlockSize+i+j] = paddedPlaintext[i+j] ^ keystream[j]
			}
			
			// Increment counter
			for j := 15; j >= 12; j-- {
				counter[j]++
				if counter[j] != 0 {
					break
				}
			}
		}

		// Calculate authentication tag
		h := getBuffer(AESBlockSize)
		defer putBuffer(h)
		blockEncrypter(h)

		j0 := getBuffer(AESBlockSize)
		defer putBuffer(j0)
		copy(j0, iv)
		j0[15] = 1

		tag := getBuffer(AESBlockSize)
		defer putBuffer(tag)
		blockEncrypter(j0)
		copy(tag, j0)

		ghash := getBuffer(AESBlockSize)
		defer putBuffer(ghash)
		
		// Hash AAD if present
		if aad != nil {
			aadBlocks := (len(aad) + AESBlockSize - 1) / AESBlockSize
			for i := 0; i < aadBlocks; i++ {
				start := i * AESBlockSize
				end := start + AESBlockSize
				if end > len(aad) {
					end = len(aad)
				}
				block := getBuffer(AESBlockSize)
				copy(block, aad[start:end])
				utils.XORBytes(ghash, block)
				ghash = utils.GaloisFieldMultiply(ghash, h)
				putBuffer(block)
			}
		}
		
		// Hash ciphertext
		ciphertextData := ciphertext[AESBlockSize : len(ciphertext)-16]
		ciphertextBlocks := (len(ciphertextData) + AESBlockSize - 1) / AESBlockSize
		for i := 0; i < ciphertextBlocks; i++ {
			start := i * AESBlockSize
			end := start + AESBlockSize
			if end > len(ciphertextData) {
				end = len(ciphertextData)
			}
			block := getBuffer(AESBlockSize)
			copy(block, ciphertextData[start:end])
			utils.XORBytes(ghash, block)
			ghash = utils.GaloisFieldMultiply(ghash, h)
			putBuffer(block)
		}

		// Include lengths
		lengths := getBuffer(16)
		if aad != nil {
			binary.BigEndian.PutUint64(lengths[:8], uint64(len(aad)*8))
		}
		binary.BigEndian.PutUint64(lengths[8:], uint64(len(ciphertextData)*8))
		utils.XORBytes(ghash, lengths)
		ghash = utils.GaloisFieldMultiply(ghash, h)
		putBuffer(lengths)

		// XOR GHASH result with tag
		for i := range tag {
			tag[i] ^= ghash[i]
		}

		// Append tag to ciphertext
		copy(ciphertext[len(ciphertext)-16:], tag)

	default:
		return nil, fmt.Errorf("unsupported mode of operation")
	}

	return ciphertext, nil
}

// Decrypt decrypts the ciphertext using the specified mode of operation
func (c *CustomAES) Decrypt(ciphertext []byte, mode BlockMode, aad []byte) ([]byte, error) {
	if len(ciphertext) < AESBlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	blockDecrypter := func(block []byte) {
		c.ctx.DecryptBlock(block)
	}

	var plaintext []byte

	switch mode {
	case ECB:
		plaintext = getBuffer(len(ciphertext))
		copy(plaintext, ciphertext)
		for i := 0; i < len(plaintext); i += AESBlockSize {
			blockDecrypter(plaintext[i : i+AESBlockSize])
		}

	case CBC:
		if len(ciphertext) <= AESBlockSize {
			return nil, fmt.Errorf("ciphertext too short for CBC mode")
		}

		iv := ciphertext[:AESBlockSize]
		plaintext = getBuffer(len(ciphertext) - AESBlockSize)
		copy(plaintext, ciphertext[AESBlockSize:])

		prevBlock := getBuffer(AESBlockSize)
		defer putBuffer(prevBlock)
		copy(prevBlock, iv)
		
		for i := 0; i < len(plaintext); i += AESBlockSize {
			block := plaintext[i : i+AESBlockSize]
			blockCopy := getBuffer(AESBlockSize)
			copy(blockCopy, block)
			
			blockDecrypter(block)
			utils.XORBytes(block, prevBlock)
			
			copy(prevBlock, blockCopy)
			putBuffer(blockCopy)
		}

	case CTR:
		if len(ciphertext) <= AESBlockSize {
			return nil, fmt.Errorf("ciphertext too short for CTR mode")
		}

		nonce := ciphertext[:AESBlockSize]
		counter := getBuffer(AESBlockSize)
		defer putBuffer(counter)
		copy(counter, nonce)

		plaintext = getBuffer(len(ciphertext) - AESBlockSize)
		keystream := getBuffer(AESBlockSize)
		defer putBuffer(keystream)

		for i := 0; i < len(plaintext); i += AESBlockSize {
			copy(keystream, counter)
			blockDecrypter(keystream)
			
			end := i + AESBlockSize
			if end > len(plaintext) {
				end = len(plaintext)
			}
			
			for j := 0; j < end-i; j++ {
				plaintext[i+j] = ciphertext[AESBlockSize+i+j] ^ keystream[j]
			}
			
			utils.IncrementCounter(counter)
		}

	case GCM:
		if len(ciphertext) <= AESBlockSize+16 {
			return nil, fmt.Errorf("ciphertext too short for GCM mode")
		}

		iv := ciphertext[:AESBlockSize]
		tag := ciphertext[len(ciphertext)-16:]
		actualCiphertext := ciphertext[AESBlockSize : len(ciphertext)-16]

		// Handle non-96-bit IVs
		if len(iv) != 12 {
			h := getBuffer(AESBlockSize)
			defer putBuffer(h)
			blockDecrypter(h)
			
			ghash := getBuffer(AESBlockSize)
			defer putBuffer(ghash)
			
			ivBlocks := (len(iv) + AESBlockSize - 1) / AESBlockSize
			for i := 0; i < ivBlocks; i++ {
				start := i * AESBlockSize
				end := start + AESBlockSize
				if end > len(iv) {
					end = len(iv)
				}
				block := getBuffer(AESBlockSize)
				copy(block, iv[start:end])
				utils.XORBytes(ghash, block)
				ghash = utils.GaloisFieldMultiply(ghash, h)
				putBuffer(block)
			}
			
			lengths := getBuffer(16)
			binary.BigEndian.PutUint64(lengths[8:], uint64(len(iv)*8))
			utils.XORBytes(ghash, lengths)
			ghash = utils.GaloisFieldMultiply(ghash, h)
			putBuffer(lengths)
			
			// Update IV
			newIV := getBuffer(AESBlockSize)
			copy(newIV, ghash)
			iv = newIV
		}

		// Calculate H = E(K, 0^128)
		h := getBuffer(AESBlockSize)
		defer putBuffer(h)
		blockDecrypter(h)

		// Calculate J0
		j0 := getBuffer(AESBlockSize)
		defer putBuffer(j0)
		copy(j0, iv)
		j0[15] = 1

		// Calculate tag
		expectedTag := getBuffer(AESBlockSize)
		defer putBuffer(expectedTag)
		blockDecrypter(j0)
		copy(expectedTag, j0)

		// GHASH calculation
		ghash := getBuffer(AESBlockSize)
		defer putBuffer(ghash)
		
		// Hash AAD if present
		if aad != nil {
			aadBlocks := (len(aad) + AESBlockSize - 1) / AESBlockSize
			for i := 0; i < aadBlocks; i++ {
				start := i * AESBlockSize
				end := start + AESBlockSize
				if end > len(aad) {
					end = len(aad)
				}
				block := getBuffer(AESBlockSize)
				copy(block, aad[start:end])
				utils.XORBytes(ghash, block)
				ghash = utils.GaloisFieldMultiply(ghash, h)
				putBuffer(block)
			}
		}
		
		// Hash ciphertext
		ciphertextBlocks := (len(actualCiphertext) + AESBlockSize - 1) / AESBlockSize
		for i := 0; i < ciphertextBlocks; i++ {
			start := i * AESBlockSize
			end := start + AESBlockSize
			if end > len(actualCiphertext) {
				end = len(actualCiphertext)
			}
			block := getBuffer(AESBlockSize)
			copy(block, actualCiphertext[start:end])
			utils.XORBytes(ghash, block)
			ghash = utils.GaloisFieldMultiply(ghash, h)
			putBuffer(block)
		}

		// Include lengths
		lengths := getBuffer(16)
		if aad != nil {
			binary.BigEndian.PutUint64(lengths[:8], uint64(len(aad)*8))
		}
		binary.BigEndian.PutUint64(lengths[8:], uint64(len(actualCiphertext)*8))
		utils.XORBytes(ghash, lengths)
		ghash = utils.GaloisFieldMultiply(ghash, h)
		putBuffer(lengths)

		// XOR GHASH result with expected tag
		for i := range expectedTag {
			expectedTag[i] ^= ghash[i]
		}

		// Verify tag in constant time
		if !utils.ConstantTimeCompare(expectedTag, tag) {
			return nil, fmt.Errorf("authentication failed")
		}

		// Decrypt using CTR mode
		counter := getBuffer(AESBlockSize)
		defer putBuffer(counter)
		copy(counter[:12], iv)
		counter[15] = 1

		plaintext = getBuffer(len(actualCiphertext))
		keystream := getBuffer(AESBlockSize)
		defer putBuffer(keystream)

		for i := 0; i < len(plaintext); i += AESBlockSize {
			copy(keystream, counter)
			blockDecrypter(keystream)
			
			end := i + AESBlockSize
			if end > len(plaintext) {
				end = len(plaintext)
			}
			
			for j := 0; j < end-i; j++ {
				plaintext[i+j] = actualCiphertext[i+j] ^ keystream[j]
			}
			
			// Increment counter
			for j := 15; j >= 12; j-- {
				counter[j]++
				if counter[j] != 0 {
					break
				}
			}
		}

	default:
		return nil, fmt.Errorf("unsupported mode of operation")
	}

	// Unpad the plaintext
	unpadded, err := utils.UnpadBlock(plaintext, AESBlockSize, utils.PKCS7Padding)
	if err != nil {
		putBuffer(plaintext) // Return buffer to pool before error
		return nil, err
	}
	
	// Create final result buffer and copy unpadded data
	result := getBuffer(len(unpadded))
	copy(result, unpadded)
	
	// Return original buffer to pool
	putBuffer(plaintext)
	
	return result, nil
}

// GetBlockSize returns the block size
func (c *CustomAES) GetBlockSize() int {
	return AESBlockSize
}

// GetName returns the name of the implementation
func (c *CustomAES) GetName() string {
	return "Custom AES"
}

// GetKeySize returns the current key size in bits
func (c *CustomAES) GetKeySize() int {
	return c.ctx.KeySize
}

// GetMode returns the current mode of operation
func (c *CustomAES) GetMode() string {
	return c.ctx.Mode
}

// IsCustomImplementation returns whether this is a custom implementation
func (c *CustomAES) IsCustomImplementation() bool {
	return true
}

// GetIVSize returns the IV size in bytes
func (c *CustomAES) GetIVSize() int {
	return AESBlockSize
}

// GetNumRounds returns the number of rounds
func (c *CustomAES) GetNumRounds() int {
	return c.ctx.numRounds
} 