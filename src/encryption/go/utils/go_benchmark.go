package utils

import (
	"runtime"
	"time"
)

// BenchmarkMetrics holds the metrics for a single benchmark run
type BenchmarkMetrics struct {
	StartTime time.Time
	EndTime   time.Time
	
	// Memory stats before operation
	InitialMemStats runtime.MemStats
	
	// Memory stats after operation
	FinalMemStats runtime.MemStats
	
	// CPU stats
	CPUStartTime time.Time
	CPUEndTime   time.Time
	CPUTimeNs    int64
	
	// Additional metrics to match C implementation
	PageFaults            int64
	CtxSwitchesVoluntary int64
	CtxSwitchesInvoluntary int64
	BlockSize            int
	IVSize              int
	NumRounds           int
}

// StartBenchmark initializes a new benchmark measurement
func StartBenchmark() *BenchmarkMetrics {
	metrics := &BenchmarkMetrics{
		StartTime:    time.Now(),
		CPUStartTime: time.Now(),
	}
	
	// Get initial memory stats
	runtime.ReadMemStats(&metrics.InitialMemStats)
	
	return metrics
}

// EndBenchmark completes the benchmark measurement
func (bm *BenchmarkMetrics) EndBenchmark() {
	bm.EndTime = time.Now()
	bm.CPUEndTime = time.Now()
	
	// Get final memory stats
	runtime.ReadMemStats(&bm.FinalMemStats)
	
	// Calculate CPU time
	bm.CPUTimeNs = bm.CPUEndTime.Sub(bm.CPUStartTime).Nanoseconds()
}

// GetElapsedTimeNs returns the elapsed time in nanoseconds
func (bm *BenchmarkMetrics) GetElapsedTimeNs() int64 {
	return bm.EndTime.Sub(bm.StartTime).Nanoseconds()
}

// GetElapsedTimeS returns the elapsed time in seconds
func (bm *BenchmarkMetrics) GetElapsedTimeS() float64 {
	return float64(bm.GetElapsedTimeNs()) / 1e9
}

// GetCPUTimeNs returns the CPU time in nanoseconds
func (bm *BenchmarkMetrics) GetCPUTimeNs() int64 {
	return bm.CPUTimeNs
}

// GetCPUTimeS returns the CPU time in seconds
func (bm *BenchmarkMetrics) GetCPUTimeS() float64 {
	return float64(bm.CPUTimeNs) / 1e9
}

// GetCPUPercent returns the CPU utilization percentage
func (bm *BenchmarkMetrics) GetCPUPercent() float64 {
	elapsedTime := float64(bm.GetElapsedTimeNs())
	if elapsedTime == 0 {
		return 0
	}
	return (float64(bm.CPUTimeNs) / elapsedTime) * 100
}

// GetPeakMemoryBytes returns the peak memory usage in bytes
func (bm *BenchmarkMetrics) GetPeakMemoryBytes() int64 {
	return int64(bm.FinalMemStats.Sys)
}

// GetPeakMemoryMB returns the peak memory usage in megabytes
func (bm *BenchmarkMetrics) GetPeakMemoryMB() float64 {
	return float64(bm.GetPeakMemoryBytes()) / (1024 * 1024)
}

// GetAllocatedMemoryBytes returns the allocated memory in bytes
func (bm *BenchmarkMetrics) GetAllocatedMemoryBytes() int64 {
	return int64(bm.FinalMemStats.Alloc - bm.InitialMemStats.Alloc)
}

// GetAllocatedMemoryMB returns the allocated memory in megabytes
func (bm *BenchmarkMetrics) GetAllocatedMemoryMB() float64 {
	return float64(bm.GetAllocatedMemoryBytes()) / (1024 * 1024)
}

// GetThroughputBps returns the throughput in bytes per second
func (bm *BenchmarkMetrics) GetThroughputBps(dataSize int64) float64 {
	elapsedTime := bm.GetElapsedTimeS()
	if elapsedTime == 0 {
		return 0
	}
	return float64(dataSize) / elapsedTime
}

// GetThroughputMBps returns the throughput in megabytes per second
func (bm *BenchmarkMetrics) GetThroughputMBps(dataSize int64) float64 {
	return bm.GetThroughputBps(dataSize) / (1024 * 1024)
} 