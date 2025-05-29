package utils

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
)

// TestConfig represents the structure of test_config.json
type TestConfig struct {
	Languages struct {
		Go bool `json:"go"`
	} `json:"languages"`
	EncryptionMethods struct {
		AES struct {
			Enabled  bool   `json:"enabled"`
			KeySize  string `json:"key_size"`
			Mode     string `json:"mode"`
		} `json:"aes"`
		ChaCha20 struct {
			Enabled bool `json:"enabled"`
		} `json:"chacha20"`
		RSA struct {
			Enabled  bool   `json:"enabled"`
			KeySize  string `json:"key_size"`
			Padding  string `json:"padding"`
		} `json:"rsa"`
		ECC struct {
			Enabled bool   `json:"enabled"`
			Curve   string `json:"curve"`
		} `json:"ecc"`
		Camellia struct {
			Enabled bool   `json:"enabled"`
			KeySize string `json:"key_size"`
			Mode    string `json:"mode"`
		} `json:"camellia"`
	} `json:"encryption_methods"`
	TestParameters struct {
		ProcessingStrategy string `json:"processing_strategy"`
		ChunkSize         string `json:"chunk_size"`
		UseStdlib         bool   `json:"use_stdlib"`
		UseCustom         bool   `json:"use_custom"`
		Iterations        int    `json:"iterations"`
		DatasetPath       string `json:"dataset_path"`
	} `json:"test_parameters"`
	SessionInfo struct {
		Timestamp    string `json:"timestamp"`
		HumanTimestamp string `json:"human_timestamp"`
		SessionDir   string `json:"session_dir"`
		SessionID    string `json:"session_id"`
	} `json:"session_info"`
}

// ParseConfig reads and parses the test configuration file
func ParseConfig(configPath string) (*TestConfig, error) {
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config TestConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// FindLatestSessionConfig finds the most recent session's test_config.json
func FindLatestSessionConfig() (string, error) {
	// Get the project root directory
	projectRoot, err := os.Getwd()
	if err != nil {
		return "", err
	}

	// Navigate to the sessions directory
	sessionsDir := filepath.Join(projectRoot, "sessions")
	
	// Read all entries in the sessions directory
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		return "", err
	}

	var latestSession string
	var latestTime int64

	// Find the most recent session directory
	for _, entry := range entries {
		if entry.IsDir() && filepath.Base(entry.Name())[:8] == "Session-" {
			path := filepath.Join(sessionsDir, entry.Name())
			info, err := os.Stat(path)
			if err != nil {
				continue
			}

			if info.ModTime().Unix() > latestTime {
				latestTime = info.ModTime().Unix()
				latestSession = path
			}
		}
	}

	if latestSession == "" {
		return "", os.ErrNotExist
	}

	// Return the path to test_config.json in the latest session
	return filepath.Join(latestSession, "test_config.json"), nil
} 