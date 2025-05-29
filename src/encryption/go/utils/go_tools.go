package utils

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"os"
)

// Common utility functions used across different encryption implementations

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