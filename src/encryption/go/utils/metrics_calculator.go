package utils

// CalculateAggregatedMetrics calculates the aggregated metrics for all iterations
func CalculateAggregatedMetrics(benchmarks *EncryptionBenchmarks) {
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
} 