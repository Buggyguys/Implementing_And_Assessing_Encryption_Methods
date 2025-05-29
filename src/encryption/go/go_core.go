// CryptoBench Pro - Go Core Implementation
// Implements benchmarking for Go encryption algorithms

package main

import (
	"encryption/utils"
	"log"
	"os"
	"encryption/aes"
)

func main() {
	// Set up logging
	log.SetPrefix("Go Core: ")
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Get config file path from command line argument or find latest session
	var configPath string
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	} else {
		var err error
		configPath, err = utils.FindLatestSessionConfig()
		if err != nil {
			log.Fatalf("Failed to find latest session config: %v", err)
		}
	}

	// Parse the configuration
	config, err := utils.ParseConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	// Check if Go tests are enabled
	if !config.Languages.Go {
		log.Println("Go tests are not enabled in configuration")
		return
	}

	// Initialize results structure
	results := utils.InitializeResults(config)

	// Get the dataset size
	datasetSize, err := utils.GetFileSize(config.TestParameters.DatasetPath)
	if err != nil {
		log.Fatalf("Failed to get dataset size: %v", err)
	}
	results.Dataset.SizeBytes = datasetSize

	// Run enabled encryption tests
	runEncryptionTests(config, results)

	// Write results
	if err := utils.WriteResults(results, config.SessionInfo.SessionDir); err != nil {
		log.Fatalf("Failed to write results: %v", err)
	}

	log.Println("Go encryption tests completed successfully")
}

func runEncryptionTests(config *utils.TestConfig, results *utils.BenchmarkResults) {
	if config.EncryptionMethods.AES.Enabled {
		log.Println("Running AES tests...")
		
		// Parse key size
		keySize := 0
		switch config.EncryptionMethods.AES.KeySize {
		case "128":
			keySize = 128
		case "192":
			keySize = 192
		case "256":
			keySize = 256
		default:
			log.Printf("Unsupported AES key size: %s", config.EncryptionMethods.AES.KeySize)
			return
		}

		// Run standard implementation if enabled
		if config.TestParameters.UseStdlib {
			log.Println("Running standard AES implementation...")
			impl := &aes.StandardAES{}
			if err := impl.Initialize(keySize, config.EncryptionMethods.AES.Mode); err != nil {
				log.Printf("Failed to initialize standard AES: %v", err)
				return
			}
			
			if err := aes.RunAESBenchmark(impl, config, results); err != nil {
				log.Printf("Failed to run standard AES benchmark: %v", err)
				return
			}
			log.Println("Standard AES implementation completed")
		}
	}

	if config.EncryptionMethods.ChaCha20.Enabled {
		log.Println("Running ChaCha20 tests...")
		// TODO: Run ChaCha20 tests
	}

	if config.EncryptionMethods.RSA.Enabled {
		log.Println("Running RSA tests...")
		// TODO: Run RSA tests
	}

	if config.EncryptionMethods.ECC.Enabled {
		log.Println("Running ECC tests...")
		// TODO: Run ECC tests
	}

	if config.EncryptionMethods.Camellia.Enabled {
		log.Println("Running Camellia tests...")
		// TODO: Run Camellia tests
	}
} 