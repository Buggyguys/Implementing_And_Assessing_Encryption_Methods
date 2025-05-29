package utils

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"os"
)

// Common utility functions used across different encryption implementations

// Precomputed tables for Galois Field operations
var (
	// Multiplication tables for x * 2, x * 4, x * 8 in GF(2^8)
	gfMul2 [256]byte
	gfMul4 [256]byte
	gfMul8 [256]byte
	
	// Lookup tables for common operations
	gfMulTable [16][256]byte
)

func init() {
	// Initialize multiplication tables
	for i := 0; i < 256; i++ {
		// x * 2
		gfMul2[i] = byte(i << 1)
		if i&0x80 != 0 {
			gfMul2[i] ^= 0x1b // Reduction polynomial for AES
		}
		
		// x * 4
		gfMul4[i] = gfMul2[gfMul2[i]]
		
		// x * 8
		gfMul8[i] = gfMul2[gfMul4[i]]
	}
	
	// Initialize lookup tables for values 0-15
	for i := 0; i < 16; i++ {
		for j := 0; j < 256; j++ {
			var result byte
			x := byte(j)
			
			// Use precomputed tables for faster multiplication
			if i&1 != 0 {
				result ^= x
			}
			if i&2 != 0 {
				result ^= gfMul2[x]
			}
			if i&4 != 0 {
				result ^= gfMul4[x]
			}
			if i&8 != 0 {
				result ^= gfMul8[x]
			}
			
			gfMulTable[i][j] = result
		}
	}
}

// GenerateRandomBytes generates a slice of random bytes of the specified size
func GenerateRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// ReadFileInChunks reads a file in chunks of specified size
func ReadFileInChunks(filePath string, chunkSize int64) (<-chan []byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	chunks := make(chan []byte)

	go func() {
		defer file.Close()
		defer close(chunks)

		for {
			chunk := make([]byte, chunkSize)
			n, err := file.Read(chunk)
			if err == io.EOF {
				break
			}
			if err != nil {
				// In a real implementation, we'd want to handle this error better
				return
			}
			if n < len(chunk) {
				chunk = chunk[:n]
			}
			chunks <- chunk
		}
	}()

	return chunks, nil
}

// GetFileSize returns the size of a file in bytes
func GetFileSize(filePath string) (int64, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// LeftRotate32 performs a 32-bit left rotation
func LeftRotate32(x uint32, n uint) uint32 {
	return (x << n) | (x >> (32 - n))
}

// RightRotate32 performs a 32-bit right rotation
func RightRotate32(x uint32, n uint) uint32 {
	return (x >> n) | (x << (32 - n))
}

// LeftRotate64 performs a 64-bit left rotation
func LeftRotate64(x uint64, n uint) uint64 {
	return (x << n) | (x >> (64 - n))
}

// RightRotate64 performs a 64-bit right rotation
func RightRotate64(x uint64, n uint) uint64 {
	return (x >> n) | (x << (64 - n))
}

// BytesToUint32 converts a byte slice to uint32 (little endian)
func BytesToUint32(b []byte) uint32 {
	return binary.LittleEndian.Uint32(b)
}

// Uint32ToBytes converts uint32 to a byte slice (little endian)
func Uint32ToBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// BytesToUint64 converts a byte slice to uint64 (little endian)
func BytesToUint64(b []byte) uint64 {
	return binary.LittleEndian.Uint64(b)
}

// Uint64ToBytes converts uint64 to a byte slice (little endian)
func Uint64ToBytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

// XORBytes performs XOR operation on two byte slices
func XORBytes(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	result := make([]byte, n)
	for i := 0; i < n; i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// CompareBytes compares two byte slices for equality in constant time
func CompareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// ConstantTimeCompare compares two byte slices in constant time
func ConstantTimeCompare(a, b []byte) bool {
	return CompareBytes(a, b)
}

// SecureRandomBytes generates cryptographically secure random bytes
// This uses the OS's secure random source (/dev/urandom on Unix systems)
func SecureRandomBytes(size int) ([]byte, error) {
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	b := make([]byte, size)
	_, err = f.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// SecureRandomInt generates a cryptographically secure random integer in [0, max)
func SecureRandomInt(max *big.Int) (*big.Int, error) {
	result, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// BlockPadding represents different padding methods for block ciphers
type BlockPadding int

const (
	PKCS7Padding BlockPadding = iota
	ISO7816Padding
	X923Padding
)

// PadBlock pads data according to the specified padding method and block size
func PadBlock(data []byte, blockSize int, padding BlockPadding) ([]byte, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("invalid block size")
	}

	padLen := blockSize - len(data)%blockSize
	padText := make([]byte, len(data)+padLen)
	copy(padText, data)

	switch padding {
	case PKCS7Padding:
		// PKCS7: All padding bytes are filled with the number of padding bytes
		for i := 0; i < padLen; i++ {
			padText[len(data)+i] = byte(padLen)
		}

	case ISO7816Padding:
		// ISO7816: First padding byte is 0x80, rest are 0x00
		padText[len(data)] = 0x80
		for i := 1; i < padLen; i++ {
			padText[len(data)+i] = 0x00
		}

	case X923Padding:
		// ANSI X.923: Last byte contains pad length, other pad bytes are zero
		for i := 0; i < padLen-1; i++ {
			padText[len(data)+i] = 0x00
		}
		padText[len(padText)-1] = byte(padLen)

	default:
		return nil, fmt.Errorf("unsupported padding method")
	}

	return padText, nil
}

// UnpadBlock removes padding according to the specified method
func UnpadBlock(data []byte, blockSize int, padding BlockPadding) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded data length")
	}

	switch padding {
	case PKCS7Padding:
		lastByte := data[len(data)-1]
		padLen := int(lastByte)

		if padLen == 0 || padLen > blockSize {
			return nil, fmt.Errorf("invalid padding length")
		}

		// Verify padding
		for i := len(data) - padLen; i < len(data); i++ {
			if data[i] != lastByte {
				return nil, fmt.Errorf("invalid padding")
			}
		}

		return data[:len(data)-padLen], nil

	case ISO7816Padding:
		// Find the 0x80 byte from the end
		for i := len(data) - 1; i >= 0; i-- {
			if data[i] == 0x80 {
				// Verify remaining padding bytes are zero
				for j := i + 1; j < len(data); j++ {
					if data[j] != 0x00 {
						return nil, fmt.Errorf("invalid padding")
					}
				}
				return data[:i], nil
			} else if data[i] != 0x00 {
				return nil, fmt.Errorf("invalid padding")
			}
		}
		return nil, fmt.Errorf("padding marker not found")

	case X923Padding:
		padLen := int(data[len(data)-1])
		if padLen == 0 || padLen > blockSize {
			return nil, fmt.Errorf("invalid padding length")
		}

		// Verify padding zeros
		for i := len(data) - padLen; i < len(data)-1; i++ {
			if data[i] != 0x00 {
				return nil, fmt.Errorf("invalid padding")
			}
		}

		return data[:len(data)-padLen], nil

	default:
		return nil, fmt.Errorf("unsupported padding method")
	}
}

// IncrementCounter increments a big-endian counter
func IncrementCounter(counter []byte) {
	for i := len(counter) - 1; i >= 0; i-- {
		counter[i]++
		if counter[i] != 0 {
			break
		}
	}
}

// GaloisFieldMultiply performs multiplication in GF(2^128) using precomputed tables
func GaloisFieldMultiply(x, y []byte) []byte {
	if len(x) != 16 || len(y) != 16 {
		panic("GaloisFieldMultiply: inputs must be 16 bytes")
	}
	
	result := make([]byte, 16)
	
	// Process 4 bytes at a time for better performance
	for i := 0; i < 16; i += 4 {
		// Load 4 bytes from y
		y0 := y[i]
		y1 := y[i+1]
		y2 := y[i+2]
		y3 := y[i+3]
		
		// Process each byte of x against the loaded y bytes
		for j := 0; j < 16; j++ {
			// Split x byte into high and low nibbles
			xb := x[j]
			high := xb >> 4
			low := xb & 0x0f
			
			// Use lookup tables for both nibbles
			result[(i+j)%16] ^= gfMulTable[high][y0] ^ gfMulTable[low][y1]
			result[(i+j+1)%16] ^= gfMulTable[high][y1] ^ gfMulTable[low][y2]
			result[(i+j+2)%16] ^= gfMulTable[high][y2] ^ gfMulTable[low][y3]
			result[(i+j+3)%16] ^= gfMulTable[high][y3] ^ gfMulTable[low][y0]
		}
	}
	
	return result
}

// GaloisFieldMultiplyByte performs multiplication of two bytes in GF(2^8)
// This is used for AES MixColumns operation
func GaloisFieldMultiplyByte(x, y byte) byte {
	var product byte = 0
	for i := 0; i < 8; i++ {
		if y&1 != 0 {
			product ^= x
		}
		highBit := x&0x80 != 0
		x <<= 1
		if highBit {
			x ^= 0x1b // AES irreducible polynomial
		}
		y >>= 1
	}
	return product
}

// SecureRandomBytesInto fills an existing buffer with random bytes
func SecureRandomBytesInto(b []byte) (int, error) {
	return rand.Read(b)
} 