package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// BenchmarkResults represents the structure for storing benchmark results
type BenchmarkResults struct {
	Timestamp       string                           `json:"timestamp"`
	SessionID       string                           `json:"session_id"`
	Language        string                           `json:"language"`
	Dataset         DatasetInfo                      `json:"dataset"`
	TestConfig      TestConfiguration                `json:"test_configuration"`
	Results         map[string]EncryptionBenchmarks  `json:"encryption_results"`
}

type DatasetInfo struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
}

type TestConfiguration struct {
	Iterations           int    `json:"iterations"`
	ProcessingStrategy   string `json:"processing_strategy"`
	UseStdlib           bool   `json:"use_stdlib_implementations"`
	UseCustom           bool   `json:"use_custom_implementations"`
}

type EncryptionBenchmarks struct {
	Iterations         []IterationMetrics     `json:"iterations"`
	AggregatedMetrics  AggregatedMetrics     `json:"aggregated_metrics"`
	Configuration      EncryptionConfig       `json:"configuration"`
	ImplementationType string                 `json:"implementation_type"`
	Description        string                 `json:"description"`
}

type IterationMetrics struct {
	Iteration                    int     `json:"iteration"`
	KeygenTimeNs                 int64   `json:"keygen_time_ns"`
	KeygenCPUTimeNs             int64   `json:"keygen_cpu_time_ns"`
	KeygenCPUPercent            float64 `json:"keygen_cpu_percent"`
	KeygenPeakMemoryBytes       int64   `json:"keygen_peak_memory_bytes"`
	KeygenAllocatedMemoryBytes  int64   `json:"keygen_allocated_memory_bytes"`
	KeygenPageFaults            int64   `json:"keygen_page_faults"`
	KeygenCtxSwitchesVoluntary  int64   `json:"keygen_ctx_switches_voluntary"`
	KeygenCtxSwitchesInvoluntary int64  `json:"keygen_ctx_switches_involuntary"`
	KeySizeBytes                int     `json:"key_size_bytes"`
	KeySizeBits                 int     `json:"key_size_bits"`
	ThreadCount                 int     `json:"thread_count"`
	ProcessPriority            int     `json:"process_priority"`
	EncryptTimeNs              int64   `json:"encrypt_time_ns"`
	EncryptCPUTimeNs          int64   `json:"encrypt_cpu_time_ns"`
	EncryptCPUPercent         float64 `json:"encrypt_cpu_percent"`
	EncryptPeakMemoryBytes    int64   `json:"encrypt_peak_memory_bytes"`
	EncryptAllocatedMemoryBytes int64 `json:"encrypt_allocated_memory_bytes"`
	EncryptPageFaults         int64   `json:"encrypt_page_faults"`
	EncryptCtxSwitchesVoluntary int64 `json:"encrypt_ctx_switches_voluntary"`
	EncryptCtxSwitchesInvoluntary int64 `json:"encrypt_ctx_switches_involuntary"`
	InputSizeBytes            int64   `json:"input_size_bytes"`
	CiphertextSizeBytes      int64   `json:"ciphertext_size_bytes"`
	DecryptTimeNs            int64   `json:"decrypt_time_ns"`
	DecryptCPUTimeNs        int64   `json:"decrypt_cpu_time_ns"`
	DecryptCPUPercent       float64 `json:"decrypt_cpu_percent"`
	DecryptPeakMemoryBytes  int64   `json:"decrypt_peak_memory_bytes"`
	DecryptAllocatedMemoryBytes int64 `json:"decrypt_allocated_memory_bytes"`
	DecryptPageFaults       int64   `json:"decrypt_page_faults"`
	DecryptCtxSwitchesVoluntary int64 `json:"decrypt_ctx_switches_voluntary"`
	DecryptCtxSwitchesInvoluntary int64 `json:"decrypt_ctx_switches_involuntary"`
	DecryptedSizeBytes     int64   `json:"decrypted_size_bytes"`
	CorrectnessChecked    bool    `json:"correctness_passed"`
	IsCustomImplementation bool    `json:"is_custom_implementation"`
	LibraryVersion        string  `json:"library_version"`
}

type AggregatedMetrics struct {
	IterationsCompleted        int     `json:"iterations_completed"`
	AllCorrectnessChecksPassed bool    `json:"all_correctness_checks_passed"`
	AvgKeygenTimeNs           int64   `json:"avg_keygen_time_ns"`
	AvgEncryptTimeNs          int64   `json:"avg_encrypt_time_ns"`
	AvgDecryptTimeNs          int64   `json:"avg_decrypt_time_ns"`
	AvgKeygenTimeS            float64 `json:"avg_keygen_time_s"`
	AvgEncryptTimeS           float64 `json:"avg_encrypt_time_s"`
	AvgDecryptTimeS           float64 `json:"avg_decrypt_time_s"`
	AvgKeygenCPUTimeNs       int64   `json:"avg_keygen_cpu_time_ns"`
	AvgEncryptCPUTimeNs      int64   `json:"avg_encrypt_cpu_time_ns"`
	AvgDecryptCPUTimeNs      int64   `json:"avg_decrypt_cpu_time_ns"`
	AvgKeygenCPUPercent      float64 `json:"avg_keygen_cpu_percent"`
	AvgEncryptCPUPercent     float64 `json:"avg_encrypt_cpu_percent"`
	AvgDecryptCPUPercent     float64 `json:"avg_decrypt_cpu_percent"`
	AvgKeygenPeakMemoryBytes int64   `json:"avg_keygen_peak_memory_bytes"`
	AvgEncryptPeakMemoryBytes int64  `json:"avg_encrypt_peak_memory_bytes"`
	AvgDecryptPeakMemoryBytes int64  `json:"avg_decrypt_peak_memory_bytes"`
	AvgKeygenPeakMemoryMB    float64 `json:"avg_keygen_peak_memory_mb"`
	AvgEncryptPeakMemoryMB   float64 `json:"avg_encrypt_peak_memory_mb"`
	AvgDecryptPeakMemoryMB   float64 `json:"avg_decrypt_peak_memory_mb"`
	AvgKeySizeBytes          int     `json:"avg_key_size_bytes"`
	AvgCiphertextSizeBytes   int64   `json:"avg_ciphertext_size_bytes"`
	ThreadCount              int     `json:"thread_count"`
	ProcessPriority         int     `json:"process_priority"`
	BlockSizeBytes         int     `json:"block_size_bytes,omitempty"`
	IVSizeBytes           int     `json:"iv_size_bytes,omitempty"`
	NumRounds             int     `json:"num_rounds,omitempty"`
	IsCustomImplementation bool    `json:"is_custom_implementation"`
	LibraryVersion        string  `json:"library_version"`
	AvgEncryptThroughputBps float64 `json:"avg_encrypt_throughput_bps"`
	AvgDecryptThroughputBps float64 `json:"avg_decrypt_throughput_bps"`
	AvgThroughputEncryptMBps float64 `json:"avg_throughput_encrypt_mb_per_s"`
	AvgThroughputDecryptMBps float64 `json:"avg_throughput_decrypt_mb_per_s"`
	AvgCiphertextOverheadPercent float64 `json:"avg_ciphertext_overhead_percent"`
	TotalKeygenTimeNs      int64   `json:"total_keygen_time_ns"`
	TotalEncryptTimeNs     int64   `json:"total_encrypt_time_ns"`
	TotalDecryptTimeNs     int64   `json:"total_decrypt_time_ns"`
	TotalNumKeys           int     `json:"total_num_keys"`
	TotalKeySizeBytes      int64   `json:"total_key_size_bytes"`
	CorrectnessFailures    int     `json:"correctness_failures"`
}

type EncryptionConfig struct {
	Enabled   bool   `json:"enabled"`
	KeySize   string `json:"key_size,omitempty"`
	Mode      string `json:"mode,omitempty"`
	IsCustom  bool   `json:"is_custom"`
}

// WriteResults writes the benchmark results to a JSON file
func WriteResults(results *BenchmarkResults, sessionDir string) error {
	// Create results directory if it doesn't exist
	resultsDir := filepath.Join(sessionDir, "results")
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return err
	}

	// Create the results file
	resultsFile := filepath.Join(resultsDir, "go_results.json")
	file, err := os.Create(resultsFile)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create JSON encoder with indentation
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "\t")

	// Write results
	if err := encoder.Encode(results); err != nil {
		return err
	}

	return nil
}

// InitializeResults creates a new BenchmarkResults structure
func InitializeResults(config *TestConfig) *BenchmarkResults {
	return &BenchmarkResults{
		Timestamp: time.Now().Format(time.RFC3339),
		SessionID: config.SessionInfo.SessionID,
		Language: "go",
		Dataset: DatasetInfo{
			Path:      config.TestParameters.DatasetPath,
			SizeBytes: 0, // This will be set when reading the dataset
		},
		TestConfig: TestConfiguration{
			Iterations:         config.TestParameters.Iterations,
			ProcessingStrategy: config.TestParameters.ProcessingStrategy,
			UseStdlib:         config.TestParameters.UseStdlib,
			UseCustom:         config.TestParameters.UseCustom,
		},
		Results: make(map[string]EncryptionBenchmarks),
	}
} 