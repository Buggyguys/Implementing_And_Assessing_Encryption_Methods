package aes

import (
	"encryption/utils"
	"fmt"
	"os"
)

// AESImplementation defines the interface that all AES implementations must satisfy
type AESImplementation interface {
	// Initialize sets up the implementation with the given key size and mode
	Initialize(keySize int, mode string) error

	// GenerateKey creates a new key of the specified size
	GenerateKey() ([]byte, error)

	// Encrypt encrypts the given data using the specified key and mode
	Encrypt(key []byte, data []byte) ([]byte, error)

	// Decrypt decrypts the given data using the specified key and mode
	Decrypt(key []byte, data []byte) ([]byte, error)

	// GetName returns the name of the implementation (e.g., "Standard AES" or "Custom AES")
	GetName() string

	// GetKeySize returns the current key size in bits
	GetKeySize() int

	// GetMode returns the current mode of operation
	GetMode() string

	// IsCustomImplementation returns whether this is a custom implementation
	IsCustomImplementation() bool
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
			ciphertext, err := impl.Encrypt(key, data)
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
			plaintext, err := impl.Decrypt(key, ciphertext)
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
				ciphertext, err := impl.Encrypt(key, chunk)
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
				plaintext, err := impl.Decrypt(key, ciphertext)
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
	calculateAggregatedMetrics(&benchmarks)

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

// calculateAggregatedMetrics calculates the aggregated metrics for all iterations
func calculateAggregatedMetrics(benchmarks *utils.EncryptionBenchmarks) {
	metrics := &benchmarks.AggregatedMetrics
	metrics.IterationsCompleted = len(benchmarks.Iterations)
	metrics.AllCorrectnessChecksPassed = true

	var totalKeygenTime, totalEncryptTime, totalDecryptTime int64
	var totalKeygenCPUTime, totalEncryptCPUTime, totalDecryptCPUTime int64
	var totalKeygenCPUPercent, totalEncryptCPUPercent, totalDecryptCPUPercent float64
	var totalEncryptThroughput, totalDecryptThroughput float64
	var maxKeygenPeakMemory, maxEncryptPeakMemory, maxDecryptPeakMemory int64
	var totalKeySizeBytes int64

	for _, iter := range benchmarks.Iterations {
		// Time metrics
		totalKeygenTime += iter.KeygenTimeNs
		totalEncryptTime += iter.EncryptTimeNs
		totalDecryptTime += iter.DecryptTimeNs

		// CPU metrics
		totalKeygenCPUTime += iter.KeygenCPUTimeNs
		totalEncryptCPUTime += iter.EncryptCPUTimeNs
		totalDecryptCPUTime += iter.DecryptCPUTimeNs
		totalKeygenCPUPercent += iter.KeygenCPUPercent
		totalEncryptCPUPercent += iter.EncryptCPUPercent
		totalDecryptCPUPercent += iter.DecryptCPUPercent

		// Memory metrics
		if iter.KeygenPeakMemoryBytes > maxKeygenPeakMemory {
			maxKeygenPeakMemory = iter.KeygenPeakMemoryBytes
		}
		if iter.EncryptPeakMemoryBytes > maxEncryptPeakMemory {
			maxEncryptPeakMemory = iter.EncryptPeakMemoryBytes
		}
		if iter.DecryptPeakMemoryBytes > maxDecryptPeakMemory {
			maxDecryptPeakMemory = iter.DecryptPeakMemoryBytes
		}

		// Calculate throughput for this iteration
		encryptThroughput := float64(iter.InputSizeBytes*8) / (float64(iter.EncryptTimeNs) / 1e9)
		decryptThroughput := float64(iter.DecryptedSizeBytes*8) / (float64(iter.DecryptTimeNs) / 1e9)
		totalEncryptThroughput += encryptThroughput
		totalDecryptThroughput += decryptThroughput

		// Key size
		totalKeySizeBytes += int64(iter.KeySizeBytes)

		// Thread count and process priority (take from last iteration)
		metrics.ThreadCount = iter.ThreadCount
		metrics.ProcessPriority = iter.ProcessPriority

		// Implementation info (take from last iteration)
		metrics.IsCustomImplementation = iter.IsCustomImplementation
		metrics.LibraryVersion = iter.LibraryVersion

		if !iter.CorrectnessChecked {
			metrics.AllCorrectnessChecksPassed = false
			metrics.CorrectnessFailures++
		}
	}

	// Calculate averages
	count := float64(len(benchmarks.Iterations))
	
	// Time metrics
	metrics.AvgKeygenTimeNs = totalKeygenTime / int64(count)
	metrics.AvgEncryptTimeNs = totalEncryptTime / int64(count)
	metrics.AvgDecryptTimeNs = totalDecryptTime / int64(count)
	metrics.AvgKeygenTimeS = float64(metrics.AvgKeygenTimeNs) / 1e9
	metrics.AvgEncryptTimeS = float64(metrics.AvgEncryptTimeNs) / 1e9
	metrics.AvgDecryptTimeS = float64(metrics.AvgDecryptTimeNs) / 1e9

	// CPU metrics
	metrics.AvgKeygenCPUTimeNs = totalKeygenCPUTime / int64(count)
	metrics.AvgEncryptCPUTimeNs = totalEncryptCPUTime / int64(count)
	metrics.AvgDecryptCPUTimeNs = totalDecryptCPUTime / int64(count)
	metrics.AvgKeygenCPUPercent = totalKeygenCPUPercent / count
	metrics.AvgEncryptCPUPercent = totalEncryptCPUPercent / count
	metrics.AvgDecryptCPUPercent = totalDecryptCPUPercent / count

	// Memory metrics
	metrics.AvgKeygenPeakMemoryBytes = maxKeygenPeakMemory
	metrics.AvgEncryptPeakMemoryBytes = maxEncryptPeakMemory
	metrics.AvgDecryptPeakMemoryBytes = maxDecryptPeakMemory
	metrics.AvgKeygenPeakMemoryMB = float64(maxKeygenPeakMemory) / (1024 * 1024)
	metrics.AvgEncryptPeakMemoryMB = float64(maxEncryptPeakMemory) / (1024 * 1024)
	metrics.AvgDecryptPeakMemoryMB = float64(maxDecryptPeakMemory) / (1024 * 1024)

	// Throughput metrics
	metrics.AvgEncryptThroughputBps = totalEncryptThroughput / count
	metrics.AvgDecryptThroughputBps = totalDecryptThroughput / count
	metrics.AvgThroughputEncryptMBps = metrics.AvgEncryptThroughputBps / (8 * 1024 * 1024)
	metrics.AvgThroughputDecryptMBps = metrics.AvgDecryptThroughputBps / (8 * 1024 * 1024)

	// Key metrics
	metrics.AvgKeySizeBytes = int(totalKeySizeBytes / int64(count))
	metrics.TotalKeySizeBytes = totalKeySizeBytes
	metrics.TotalNumKeys = len(benchmarks.Iterations)

	// Store totals
	metrics.TotalKeygenTimeNs = totalKeygenTime
	metrics.TotalEncryptTimeNs = totalEncryptTime
	metrics.TotalDecryptTimeNs = totalDecryptTime

	// Calculate ciphertext overhead
	if len(benchmarks.Iterations) > 0 {
		lastIter := benchmarks.Iterations[len(benchmarks.Iterations)-1]
		if lastIter.InputSizeBytes > 0 {
			overhead := float64(lastIter.CiphertextSizeBytes - lastIter.InputSizeBytes)
			metrics.AvgCiphertextOverheadPercent = (overhead / float64(lastIter.InputSizeBytes)) * 100
		}
		metrics.AvgCiphertextSizeBytes = lastIter.CiphertextSizeBytes
	}

	// AES-specific metrics
	mode := benchmarks.Configuration.Mode
	switch mode {
	case "ECB", "CBC", "CTR", "GCM":
		metrics.BlockSizeBytes = 16 // AES always uses 16-byte blocks
		metrics.IVSizeBytes = 16    // AES modes use 16-byte IV/nonce
		switch benchmarks.Configuration.KeySize {
		case "128":
			metrics.NumRounds = 10
		case "192":
			metrics.NumRounds = 12
		case "256":
			metrics.NumRounds = 14
		}
	}
}
