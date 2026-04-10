#pragma once
/// Multi-threaded memory scanner.
/// Ports the core algorithm from CE's memscan.pas.

#include "core/types.hpp"
#include "platform/process_api.hpp"
#include <functional>
#include <atomic>
#include <filesystem>

namespace ce {

/// Configuration for a memory scan.
struct ScanConfig {
    ValueType   valueType    = ValueType::Int32;
    ScanCompare compareType  = ScanCompare::Exact;
    size_t      alignment    = 4;        // Scan alignment (1=unaligned, 2, 4, 8)
    uintptr_t   startAddress = 0;
    uintptr_t   stopAddress  = 0x7FFFFFFFFFFF;
    bool        scanWritableOnly   = false;
    bool        scanExecutableOnly = false;
    int         roundingType       = 0;   // 0=exact, 1=rounded, 2=truncated
    double      floatTolerance     = 0.0; // For rounded comparison
    bool        percentageScan     = false;
    double      percentageValue    = 0.0;

    // Search values (interpretation depends on valueType + compareType)
    int64_t     intValue     = 0;
    int64_t     intValue2    = 0;  // For "between" comparisons
    double      floatValue   = 0;
    double      floatValue2  = 0;
    std::string stringValue;
    std::vector<uint8_t> byteArray;
    std::vector<bool> byteArrayMask; // true = must match, false = wildcard (??)
    std::string binaryString;        // Binary pattern: "0110??01" (? = wildcard bit)

    /// Parse an AOB pattern like "7F 45 ?? 46" into byteArray + byteArrayMask
    void parseAOB(const std::string& pattern);

    /// Parse a binary pattern like "0110??01" into byteArray + mask
    void parseBinary(const std::string& pattern);
};

/// Holds scan results on disk. Supports iteration without loading all into memory.
class ScanResult {
public:
    ScanResult() = default;
    explicit ScanResult(const std::filesystem::path& dir);

    size_t count() const { return count_; }
    bool empty() const { return count_ == 0; }

    /// Read address at index i.
    uintptr_t address(size_t i) const;

    /// Read value bytes at index i.
    void value(size_t i, void* buf, size_t valueSize) const;

    /// Iterate all results.
    void forEach(std::function<void(uintptr_t addr, const void* value, size_t valueSize)> callback, size_t valueSize) const;

    const std::filesystem::path& directory() const { return dir_; }

    /// Add a result (used during scanning).
    void addResult(uintptr_t addr, const void* value, size_t valueSize);

    /// Flush buffered results to disk.
    void flush();

    /// Finalize (close files, update count).
    void finalize();

private:
    std::filesystem::path dir_;
    size_t count_ = 0;
    size_t valueSize_ = 0;

    // Write buffers
    std::vector<uintptr_t> addrBuf_;
    std::vector<uint8_t> valueBuf_;
    int addrFd_ = -1;
    int valueFd_ = -1;
};

/// The memory scanner engine.
class MemoryScanner {
public:
    explicit MemoryScanner(int threadCount = 0); // 0 = auto (CPU count)

    /// First scan — searches all readable memory regions for the value.
    ScanResult firstScan(ProcessHandle& proc, const ScanConfig& config);

    /// Next scan — narrows previous results.
    ScanResult nextScan(ProcessHandle& proc, const ScanConfig& config, const ScanResult& previous);

    /// Progress (0.0 to 1.0).
    float progress() const { return progress_.load(std::memory_order_relaxed); }

    /// Cancel a running scan.
    void cancel() { cancelled_.store(true, std::memory_order_relaxed); }

private:
    int threadCount_;
    std::atomic<float> progress_{0};
    std::atomic<bool> cancelled_{false};

    static size_t valueSizeFor(ValueType vt);
};

} // namespace ce
