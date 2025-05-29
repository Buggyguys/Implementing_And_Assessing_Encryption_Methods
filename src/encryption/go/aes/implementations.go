package aes

import (
	"encryption/utils"
	"fmt"
	"os"
)

// BlockMode represents different block cipher modes of operation
type BlockMode int

const (
	ECB BlockMode = iota // Electronic Codebook
	CBC                  // Cipher Block Chaining
	CTR                  // Counter
	GCM                  // Galois/Counter Mode
)

// AESImplementation defines the interface that all AES implementations must satisfy
type AESImplementation interface {
	// Initialize sets up the implementation with the given key size and mode
	Initialize(keySize int, mode string) error

	// GenerateKey creates a new key of the specified size
	GenerateKey() ([]byte, error)

	// GetName returns the name of the implementation (e.g., "Standard AES" or "Custom AES")
	GetName() string

	// GetKeySize returns the current key size in bits
	GetKeySize() int

	// GetMode returns the current mode of operation
	GetMode() string

	// IsCustomImplementation returns whether this is a custom implementation
	IsCustomImplementation() bool

	// Encrypt encrypts the plaintext using the specified mode
	// For GCM mode, the aad parameter provides Additional Authenticated Data
	// For other modes, aad is ignored and can be nil
	Encrypt(plaintext []byte, mode BlockMode, aad []byte) ([]byte, error)

	// Decrypt decrypts the ciphertext using the specified mode
	// For GCM mode, the aad parameter provides Additional Authenticated Data
	// For other modes, aad is ignored and can be nil
	Decrypt(ciphertext []byte, mode BlockMode, aad []byte) ([]byte, error)

	// GetBlockSize returns the block size in bytes
	GetBlockSize() int
}

// RunAESBenchmark runs the benchmark for a specific AES implementation
func RunAESBenchmark(impl AESImplementation, config *utils.TestConfig, results *utils.BenchmarkResults) error {
	// Create a new entry in results for this implementation
	benchmarkName := "aes"
	if impl.IsCustomImplementation() {
		benchmarkName += "_custom"
	}

	// Initialize benchmark metrics
	benchmarks := utils.EncryptionBenchmarks{
		Iterations:         make([]utils.IterationMetrics, config.TestParameters.Iterations),
		Configuration: utils.EncryptionConfig{
			Enabled:  true,
			KeySize:  config.EncryptionMethods.AES.KeySize,
			Mode:     config.EncryptionMethods.AES.Mode,
			IsCustom: impl.IsCustomImplementation(),
		},
		ImplementationType: impl.GetName(),
		Description:       impl.GetName() + " Implementation",
	}

	// Run the iterations
	for i := 0; i < config.TestParameters.Iterations; i++ {
		metrics := &benchmarks.Iterations[i]
		metrics.Iteration = i + 1
		metrics.IsCustomImplementation = impl.IsCustomImplementation()
		metrics.LibraryVersion = "OpenSSL"
		if impl.IsCustomImplementation() {
			metrics.LibraryVersion = "custom"
		}

		// Key generation benchmark
		keygenMetrics := utils.StartBenchmark()
		key, err := impl.GenerateKey()
		if err != nil {
			return err
		}
		keygenMetrics.EndBenchmark()

		metrics.KeygenTimeNs = keygenMetrics.GetElapsedTimeNs()
		metrics.KeygenCPUTimeNs = keygenMetrics.GetCPUTimeNs()
		metrics.KeygenCPUPercent = keygenMetrics.GetCPUPercent()
		metrics.KeygenPeakMemoryBytes = keygenMetrics.GetPeakMemoryBytes()
		metrics.KeygenAllocatedMemoryBytes = keygenMetrics.GetAllocatedMemoryBytes()
		metrics.KeySizeBytes = len(key)
		metrics.KeySizeBits = len(key) * 8

		// Process data based on strategy
		if config.TestParameters.ProcessingStrategy == "Memory" {
			// Read entire file
			data, err := os.ReadFile(config.TestParameters.DatasetPath)
			if err != nil {
				return err
			}

			// Encryption benchmark
			encryptMetrics := utils.StartBenchmark()
			ciphertext, err := impl.Encrypt(data, ECB, nil)
			if err != nil {
				return err
			}
			encryptMetrics.EndBenchmark()

			metrics.EncryptTimeNs = encryptMetrics.GetElapsedTimeNs()
			metrics.EncryptCPUTimeNs = encryptMetrics.GetCPUTimeNs()
			metrics.EncryptCPUPercent = encryptMetrics.GetCPUPercent()
			metrics.EncryptPeakMemoryBytes = encryptMetrics.GetPeakMemoryBytes()
			metrics.EncryptAllocatedMemoryBytes = encryptMetrics.GetAllocatedMemoryBytes()
			metrics.InputSizeBytes = int64(len(data))
			metrics.CiphertextSizeBytes = int64(len(ciphertext))

			// Decryption benchmark
			decryptMetrics := utils.StartBenchmark()
			plaintext, err := impl.Decrypt(ciphertext, ECB, nil)
			if err != nil {
				return err
			}
			decryptMetrics.EndBenchmark()

			metrics.DecryptTimeNs = decryptMetrics.GetElapsedTimeNs()
			metrics.DecryptCPUTimeNs = decryptMetrics.GetCPUTimeNs()
			metrics.DecryptCPUPercent = decryptMetrics.GetCPUPercent()
			metrics.DecryptPeakMemoryBytes = decryptMetrics.GetPeakMemoryBytes()
			metrics.DecryptAllocatedMemoryBytes = decryptMetrics.GetAllocatedMemoryBytes()
			metrics.DecryptedSizeBytes = int64(len(plaintext))

			// Check correctness
			metrics.CorrectnessChecked = utils.CompareBytes(data, plaintext)

		} else {
			// Stream processing
			chunkSize, err := parseChunkSize(config.TestParameters.ChunkSize)
			if err != nil {
				return err
			}

			chunks, err := utils.ReadFileInChunks(config.TestParameters.DatasetPath, chunkSize)
			if err != nil {
				return err
			}

			var totalInputSize, totalCiphertextSize, totalDecryptedSize int64
			var allChunksCorrect = true

			// Process each chunk
			for chunk := range chunks {
				// Encryption
				encryptMetrics := utils.StartBenchmark()
				ciphertext, err := impl.Encrypt(chunk, ECB, nil)
				if err != nil {
					return err
				}
				encryptMetrics.EndBenchmark()

				// Update encryption metrics
				metrics.EncryptTimeNs += encryptMetrics.GetElapsedTimeNs()
				metrics.EncryptCPUTimeNs += encryptMetrics.GetCPUTimeNs()
				if encryptMetrics.GetPeakMemoryBytes() > metrics.EncryptPeakMemoryBytes {
					metrics.EncryptPeakMemoryBytes = encryptMetrics.GetPeakMemoryBytes()
				}
				metrics.EncryptAllocatedMemoryBytes += encryptMetrics.GetAllocatedMemoryBytes()

				// Decryption
				decryptMetrics := utils.StartBenchmark()
				plaintext, err := impl.Decrypt(ciphertext, ECB, nil)
				if err != nil {
					return err
				}
				decryptMetrics.EndBenchmark()

				// Update decryption metrics
				metrics.DecryptTimeNs += decryptMetrics.GetElapsedTimeNs()
				metrics.DecryptCPUTimeNs += decryptMetrics.GetCPUTimeNs()
				if decryptMetrics.GetPeakMemoryBytes() > metrics.DecryptPeakMemoryBytes {
					metrics.DecryptPeakMemoryBytes = decryptMetrics.GetPeakMemoryBytes()
				}
				metrics.DecryptAllocatedMemoryBytes += decryptMetrics.GetAllocatedMemoryBytes()

				// Update sizes
				totalInputSize += int64(len(chunk))
				totalCiphertextSize += int64(len(ciphertext))
				totalDecryptedSize += int64(len(plaintext))

				// Check correctness for this chunk
				if !utils.CompareBytes(chunk, plaintext) {
					allChunksCorrect = false
				}
			}

			// Set final metrics for stream processing
			metrics.InputSizeBytes = totalInputSize
			metrics.CiphertextSizeBytes = totalCiphertextSize
			metrics.DecryptedSizeBytes = totalDecryptedSize
			metrics.CorrectnessChecked = allChunksCorrect

			// Calculate CPU percentages for stream processing
			metrics.EncryptCPUPercent = (float64(metrics.EncryptCPUTimeNs) / float64(metrics.EncryptTimeNs)) * 100
			metrics.DecryptCPUPercent = (float64(metrics.DecryptCPUTimeNs) / float64(metrics.DecryptTimeNs)) * 100
		}
	}

	// Calculate aggregated metrics
	utils.CalculateAggregatedMetrics(&benchmarks)

	// Add the benchmarks to the results
	results.Results[benchmarkName] = benchmarks

	return nil
}

// Helper function to parse chunk size string (e.g., "1MB") into bytes
func parseChunkSize(sizeStr string) (int64, error) {
	var size int64
	var unit string
	_, err := fmt.Sscanf(sizeStr, "%d%s", &size, &unit)
	if err != nil {
		return 0, err
	}

	switch unit {
	case "B":
		return size, nil
	case "KB":
		return size * 1024, nil
	case "MB":
		return size * 1024 * 1024, nil
	case "GB":
		return size * 1024 * 1024 * 1024, nil
	default:
		return 0, fmt.Errorf("unknown unit: %s", unit)
	}
}

// String returns the string representation of the block mode
func (m BlockMode) String() string {
	switch m {
	case ECB:
		return "ECB"
	case CBC:
		return "CBC"
	case CTR:
		return "CTR"
	case GCM:
		return "GCM"
	default:
		return "Unknown"
	}
}
