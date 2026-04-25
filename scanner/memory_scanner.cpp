#include "scanner/memory_scanner.hpp"

#include <thread>
#include <mutex>
#include <sstream>
#include <cstring>
#include <cmath>
#include <type_traits>
#include <stdexcept>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

namespace ce {

// ── Value size lookup ──

size_t MemoryScanner::valueSizeFor(ValueType vt) {
    switch (vt) {
        case ValueType::Byte:    return 1;
        case ValueType::Int16:   return 2;
        case ValueType::Int32:   return 4;
        case ValueType::Int64:   return 8;
        case ValueType::Float:   return 4;
        case ValueType::Double:  return 8;
        default:                 return 4;
    }
}

// ── Comparison functions ──

namespace {

template<typename T>
using CompareFn = bool(*)(T current, T scanVal, T scanVal2);

template<typename T> bool cmpExact(T c, T v, T)          { return c == v; }
template<typename T> bool cmpGreater(T c, T v, T)        { return c > v; }
template<typename T> bool cmpLess(T c, T v, T)           { return c < v; }
template<typename T> bool cmpBetween(T c, T v, T v2)     { return c >= v && c <= v2; }
template<typename T> bool cmpChanged(T c, T v, T)        { return c != v; }
template<typename T> bool cmpUnchanged(T c, T v, T)      { return c == v; }
template<typename T> bool cmpIncreased(T c, T v, T)      { return c > v; }
template<typename T> bool cmpDecreased(T c, T v, T)      { return c < v; }
template<typename T> bool cmpUnknown(T, T, T)             { return true; }

template<typename T>
CompareFn<T> getCompare(ScanCompare cmp) {
    switch (cmp) {
        case ScanCompare::Exact:     return cmpExact<T>;
        case ScanCompare::Greater:   return cmpGreater<T>;
        case ScanCompare::Less:      return cmpLess<T>;
        case ScanCompare::Between:   return cmpBetween<T>;
        case ScanCompare::Changed:   return cmpChanged<T>;
        case ScanCompare::Unchanged: return cmpUnchanged<T>;
        case ScanCompare::Increased: return cmpIncreased<T>;
        case ScanCompare::Decreased: return cmpDecreased<T>;
        case ScanCompare::Unknown:   return cmpUnknown<T>;
        default:                     return cmpExact<T>;
    }
}

template<typename T>
bool compareFloatingExact(const ScanConfig& config, T current, T scanVal) {
    if (!std::isfinite(static_cast<double>(current))) return false;

    switch (config.roundingType) {
        case 1:
            return std::llround(current) == std::llround(scanVal);
        case 2:
            return std::trunc(current) == std::trunc(scanVal);
        case 3: {
            double tolerance = config.floatTolerance > 0.0
                ? config.floatTolerance
                : std::max(1e-6, std::abs(static_cast<double>(scanVal)) * 1e-6);
            return std::abs(static_cast<double>(current) - static_cast<double>(scanVal)) <= tolerance;
        }
        default:
            return current == scanVal;
    }
}

template<typename T>
bool compareFloating(const ScanConfig& config, T current, T scanVal, T scanVal2) {
    if (config.compareType == ScanCompare::Exact)
        return compareFloatingExact(config, current, scanVal);
    return getCompare<T>(config.compareType)(current, scanVal, scanVal2);
}

bool supportsPercentageCompare(ScanCompare cmp) {
    switch (cmp) {
        case ScanCompare::Greater:
        case ScanCompare::Less:
        case ScanCompare::Between:
        case ScanCompare::Increased:
        case ScanCompare::Decreased:
            return true;
        default:
            return false;
    }
}

template<typename T>
bool comparePercentage(const ScanConfig& config, T current, T old) {
    double base = std::abs(static_cast<double>(old));
    if (base == 0.0) return false;

    double deltaPct = ((static_cast<double>(current) - static_cast<double>(old)) / base) * 100.0;
    switch (config.compareType) {
        case ScanCompare::Increased:
        case ScanCompare::Greater:
            return deltaPct >= config.percentageValue;
        case ScanCompare::Decreased:
        case ScanCompare::Less:
            return deltaPct <= -config.percentageValue;
        case ScanCompare::Between: {
            double lo = std::min(config.percentageValue, config.percentageValue2);
            double hi = std::max(config.percentageValue, config.percentageValue2);
            return deltaPct >= lo && deltaPct <= hi;
        }
        default:
            return false;
    }
}

template<typename T>
void scanBufferFloating(const uint8_t* buf, size_t bufSize, uintptr_t baseAddr,
                        size_t alignment, const ScanConfig& config, ScanResult& result)
{
    if (bufSize < sizeof(T)) return;
    size_t limit = bufSize - sizeof(T) + 1;

    T scanVal = static_cast<T>(config.floatValue);
    T scanVal2 = static_cast<T>(config.floatValue2);
    for (size_t offset = 0; offset < limit; offset += alignment) {
        T current;
        std::memcpy(&current, buf + offset, sizeof(T));
        if (compareFloating(config, current, scanVal, scanVal2))
            result.addResult(baseAddr + offset, &current, sizeof(T));
    }
}

/// Scan a buffer for matching values of type T.
template<typename T>
void scanBuffer(const uint8_t* buf, size_t bufSize, uintptr_t baseAddr,
                size_t alignment, T scanVal, T scanVal2, CompareFn<T> compare,
                ScanResult& result)
{
    if (bufSize < sizeof(T)) return;
    size_t limit = bufSize - sizeof(T) + 1;

    for (size_t offset = 0; offset < limit; offset += alignment) {
        T current;
        std::memcpy(&current, buf + offset, sizeof(T));
        if (compare(current, scanVal, scanVal2)) {
            result.addResult(baseAddr + offset, &current, sizeof(T));
        }
    }
}

/// Scan buffer for a string (exact substring match).
void scanBufferString(const uint8_t* buf, size_t bufSize, uintptr_t baseAddr,
                      const std::string& needle, ScanResult& result)
{
    if (needle.empty() || bufSize < needle.size()) return;
    const uint8_t* n = (const uint8_t*)needle.data();
    size_t nLen = needle.size();
    size_t limit = bufSize - nLen + 1;

    for (size_t offset = 0; offset < limit; ++offset) {
        if (std::memcmp(buf + offset, n, nLen) == 0) {
            result.addResult(baseAddr + offset, buf + offset, nLen);
        }
    }
}

/// Scan buffer for a UTF-16LE string.
void scanBufferUnicode(const uint8_t* buf, size_t bufSize, uintptr_t baseAddr,
                       const std::string& needle, ScanResult& result)
{
    // Convert UTF-8 needle to UTF-16LE
    std::vector<uint16_t> wide;
    for (char c : needle) wide.push_back((uint16_t)(uint8_t)c); // Simple ASCII→UTF-16
    size_t nBytes = wide.size() * 2;
    if (nBytes == 0 || bufSize < nBytes) return;

    const uint8_t* n = (const uint8_t*)wide.data();
    size_t limit = bufSize - nBytes + 1;

    for (size_t offset = 0; offset < limit; offset += 2) {
        if (std::memcmp(buf + offset, n, nBytes) == 0) {
            result.addResult(baseAddr + offset, buf + offset, nBytes);
        }
    }
}

/// Scan buffer for an array of bytes with wildcard mask.
void scanBufferAOB(const uint8_t* buf, size_t bufSize, uintptr_t baseAddr,
                   const std::vector<uint8_t>& pattern, const std::vector<bool>& mask,
                   ScanResult& result)
{
    if (pattern.empty() || mask.size() != pattern.size() || bufSize < pattern.size()) return;
    size_t pLen = pattern.size();
    size_t limit = bufSize - pLen + 1;

    for (size_t offset = 0; offset < limit; ++offset) {
        bool match = true;
        for (size_t j = 0; j < pLen; ++j) {
            if (mask[j] && buf[offset + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            result.addResult(baseAddr + offset, buf + offset, pLen);
        }
    }
}

/// Scan buffer for binary pattern with bitmask wildcards.
/// Pattern bytes and mask bytes: mask bit 1 = must match, 0 = wildcard.
void scanBufferBinary(const uint8_t* buf, size_t bufSize, uintptr_t baseAddr,
                      const std::vector<uint8_t>& pattern, const std::vector<uint8_t>& mask,
                      size_t alignment, ScanResult& result)
{
    if (pattern.empty() || bufSize < pattern.size()) return;
    size_t pLen = pattern.size();
    size_t limit = bufSize - pLen + 1;

    for (size_t offset = 0; offset < limit; offset += alignment) {
        bool match = true;
        for (size_t j = 0; j < pLen; ++j) {
            if ((buf[offset + j] & mask[j]) != (pattern[j] & mask[j])) {
                match = false;
                break;
            }
        }
        if (match) {
            result.addResult(baseAddr + offset, buf + offset, pLen);
        }
    }
}

/// "All Types" scan — scan for byte, int16, int32, int64, float, double simultaneously.
void scanBufferAllTypes(const uint8_t* buf, size_t bufSize, uintptr_t baseAddr,
                        size_t alignment, int64_t intVal, double floatVal,
                        ScanCompare cmp, ScanResult& result)
{
    auto cmpI8  = getCompare<int8_t>(cmp);
    auto cmpI16 = getCompare<int16_t>(cmp);
    auto cmpI32 = getCompare<int32_t>(cmp);
    auto cmpI64 = getCompare<int64_t>(cmp);
    auto cmpF32 = getCompare<float>(cmp);
    auto cmpF64 = getCompare<double>(cmp);

    for (size_t offset = 0; offset < bufSize; offset += alignment) {
        // Byte
        if (offset < bufSize) {
            int8_t v; std::memcpy(&v, buf + offset, 1);
            if (cmpI8(v, (int8_t)intVal, 0))
                result.addResult(baseAddr + offset, &v, 1);
        }
        // Int16
        if (offset + 2 <= bufSize) {
            int16_t v; std::memcpy(&v, buf + offset, 2);
            if (cmpI16(v, (int16_t)intVal, 0))
                result.addResult(baseAddr + offset, &v, 2);
        }
        // Int32
        if (offset + 4 <= bufSize) {
            int32_t v; std::memcpy(&v, buf + offset, 4);
            if (cmpI32(v, (int32_t)intVal, 0))
                result.addResult(baseAddr + offset, &v, 4);
        }
        // Int64
        if (offset + 8 <= bufSize) {
            int64_t v; std::memcpy(&v, buf + offset, 8);
            if (cmpI64(v, intVal, 0))
                result.addResult(baseAddr + offset, &v, 8);
        }
        // Float
        if (offset + 4 <= bufSize) {
            float v; std::memcpy(&v, buf + offset, 4);
            if (!std::isnan(v) && !std::isinf(v) && std::abs(v) < 1e15 && std::abs(v) > 1e-15)
                if (cmpF32(v, (float)floatVal, 0))
                    result.addResult(baseAddr + offset, &v, 4);
        }
        // Double
        if (offset + 8 <= bufSize) {
            double v; std::memcpy(&v, buf + offset, 8);
            if (!std::isnan(v) && !std::isinf(v) && std::abs(v) < 1e100 && std::abs(v) > 1e-100)
                if (cmpF64(v, floatVal, 0))
                    result.addResult(baseAddr + offset, &v, 8);
        }
    }
}

std::vector<uint8_t> utf16LeBytes(const std::string& text) {
    std::vector<uint8_t> bytes;
    bytes.reserve(text.size() * 2);
    for (char c : text) {
        bytes.push_back(static_cast<uint8_t>(c));
        bytes.push_back(0);
    }
    return bytes;
}

size_t valueSizeForConfig(const ScanConfig& config) {
    switch (config.valueType) {
        case ValueType::String:
            return std::max<size_t>(1, config.stringValue.size());
        case ValueType::UnicodeString:
            return std::max<size_t>(2, config.stringValue.size() * 2);
        case ValueType::ByteArray:
        case ValueType::Binary:
            return std::max<size_t>(1, config.byteArray.size());
        case ValueType::Byte:
            return 1;
        case ValueType::Int16:
            return 2;
        case ValueType::Int32:
        case ValueType::Float:
            return 4;
        case ValueType::Int64:
        case ValueType::Double:
            return 8;
        default:
            return 4;
    }
}

template<typename T>
bool compareNextNumeric(const ScanConfig& config, const uint8_t* currentVal, const uint8_t* oldVal) {
    T cur{};
    T old{};
    std::memcpy(&cur, currentVal, sizeof(T));
    std::memcpy(&old, oldVal, sizeof(T));

    if (config.percentageScan && supportsPercentageCompare(config.compareType))
        return comparePercentage(config, cur, old);

    auto cmp = getCompare<T>(config.compareType);
    if (config.compareType >= ScanCompare::Changed)
        return cmp(cur, old, T{});

    if constexpr (std::is_floating_point_v<T>) {
        T v1 = static_cast<T>(config.floatValue);
        T v2 = static_cast<T>(config.floatValue2);
        return compareFloating(config, cur, v1, v2);
    } else {
        return cmp(cur, static_cast<T>(config.intValue), static_cast<T>(config.intValue2));
    }
}

bool compareMaskedBytes(const uint8_t* currentVal,
                        const std::vector<uint8_t>& pattern,
                        const std::vector<bool>& mask) {
    if (pattern.empty()) return false;
    for (size_t i = 0; i < pattern.size(); ++i) {
        if (i < mask.size() && !mask[i]) continue;
        if (currentVal[i] != pattern[i]) return false;
    }
    return true;
}

bool memoryTypeAllowed(const ScanConfig& config, MemType type) {
    switch (type) {
        case MemType::Private: return config.scanPrivate;
        case MemType::Image:   return config.scanImage;
        case MemType::Mapped:  return config.scanMapped;
    }
    return false;
}

} // anonymous namespace

// ── AOB pattern parser ──

void ScanConfig::parseAOB(const std::string& pattern) {
    byteArray.clear();
    byteArrayMask.clear();
    std::istringstream ss(pattern);
    std::string token;
    while (ss >> token) {
        if (token == "??" || token == "?") {
            byteArray.push_back(0);
            byteArrayMask.push_back(false);
        } else {
            byteArray.push_back((uint8_t)strtoul(token.c_str(), nullptr, 16));
            byteArrayMask.push_back(true);
        }
    }
}

void ScanConfig::parseBinary(const std::string& pattern) {
    // Parse binary string like "0110??01" into bytes + mask
    // Every 8 bits = 1 byte. ? = wildcard bit.
    byteArray.clear();
    byteArrayMask.clear();
    byteMask.clear();

    uint8_t currentByte = 0, currentMask = 0;
    int bitCount = 0;

    for (char c : pattern) {
        if (c == ' ') continue;
        if (c == '0' || c == '1' || c == '?' || c == '*') {
            currentByte <<= 1;
            currentMask <<= 1;
            if (c == '1') { currentByte |= 1; currentMask |= 1; }
            else if (c == '0') { currentMask |= 1; }
            // '?' and '*' leave both as 0 (wildcard)
            bitCount++;
            if (bitCount == 8) {
                byteArray.push_back(currentByte);
                byteMask.push_back(currentMask);
                currentByte = 0;
                currentMask = 0;
                bitCount = 0;
            }
        }
    }
    // Handle partial last byte
    if (bitCount > 0) {
        currentByte <<= (8 - bitCount);
        currentMask <<= (8 - bitCount);
        byteArray.push_back(currentByte);
        byteMask.push_back(currentMask);
    }
    binaryString = pattern; // Keep original for reference
    byteArrayMask.resize(byteMask.size());
    for (size_t i = 0; i < byteMask.size(); ++i)
        byteArrayMask[i] = byteMask[i] != 0;
}

// ── ScanResult ──

ScanResult::ScanResult(const std::filesystem::path& dir) : dir_(dir) {
    auto addrPath = dir / "addresses.bin";
    auto valPath  = dir / "values.bin";

    if (std::filesystem::exists(addrPath)) {
        // Loading existing scan results (read-only mode)
        count_ = std::filesystem::file_size(addrPath) / sizeof(uintptr_t);
        addrFd_ = -1;
        valueFd_ = -1;
    } else {
        // Creating new scan results (write mode)
        std::filesystem::create_directories(dir);
        addrFd_ = open(addrPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        valueFd_ = open(valPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        addrBuf_.reserve(8192);
        valueBuf_.reserve(8192 * 8);
    }
}

void ScanResult::addResult(uintptr_t addr, const void* value, size_t valueSize) {
    addrBuf_.push_back(addr);
    size_t pos = valueBuf_.size();
    valueBuf_.resize(pos + valueSize);
    std::memcpy(valueBuf_.data() + pos, value, valueSize);
    valueSize_ = valueSize;
    ++count_;

    if (addrBuf_.size() >= 8192)
        flush();
}

void ScanResult::flush() {
    if (addrBuf_.empty()) return;
    if (addrFd_ >= 0)
        ::write(addrFd_, addrBuf_.data(), addrBuf_.size() * sizeof(uintptr_t));
    if (valueFd_ >= 0)
        ::write(valueFd_, valueBuf_.data(), valueBuf_.size());
    addrBuf_.clear();
    valueBuf_.clear();
}

void ScanResult::finalize() {
    flush();
    if (addrFd_ >= 0) { close(addrFd_); addrFd_ = -1; }
    if (valueFd_ >= 0) { close(valueFd_); valueFd_ = -1; }
}

uintptr_t ScanResult::address(size_t i) const {
    uintptr_t addr;
    auto path = dir_ / "addresses.bin";
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return 0;
    pread(fd, &addr, sizeof(addr), i * sizeof(uintptr_t));
    close(fd);
    return addr;
}

void ScanResult::value(size_t i, void* buf, size_t valueSize) const {
    auto path = dir_ / "values.bin";
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return;
    pread(fd, buf, valueSize, i * valueSize);
    close(fd);
}

void ScanResult::forEach(std::function<void(uintptr_t, const void*, size_t)> callback, size_t valueSize) const {
    auto addrPath = dir_ / "addresses.bin";
    auto valPath  = dir_ / "values.bin";
    int afd = open(addrPath.c_str(), O_RDONLY);
    int vfd = open(valPath.c_str(), O_RDONLY);
    if (afd < 0 || vfd < 0) {
        if (afd >= 0) close(afd);
        if (vfd >= 0) close(vfd);
        return;
    }

    constexpr size_t BATCH = 4096;
    std::vector<uintptr_t> addrs(BATCH);
    std::vector<uint8_t> vals(BATCH * valueSize);

    size_t remaining = count_;
    while (remaining > 0) {
        size_t n = std::min(remaining, BATCH);
        ::read(afd, addrs.data(), n * sizeof(uintptr_t));
        ::read(vfd, vals.data(), n * valueSize);
        for (size_t i = 0; i < n; ++i)
            callback(addrs[i], vals.data() + i * valueSize, valueSize);
        remaining -= n;
    }
    close(afd);
    close(vfd);
}

// ── MemoryScanner ──

MemoryScanner::MemoryScanner(int threadCount)
    : threadCount_(threadCount > 0 ? threadCount : std::thread::hardware_concurrency())
{
    if (threadCount_ < 1) threadCount_ = 1;
}

static std::atomic<uint64_t> scanCounter{0};

static std::filesystem::path makeScanDir() {
    return std::filesystem::temp_directory_path() / "ce-scan" /
           ("scan-" + std::to_string(getpid()) + "-" + std::to_string(scanCounter.fetch_add(1)));
}

ScanResult MemoryScanner::firstScan(ProcessHandle& proc, const ScanConfig& config) {
    cancelled_.store(false);
    progress_.store(0);

    if (config.valueType == ValueType::Custom)
        throw std::invalid_argument("ValueType::Custom requires a registered custom scanner");

    // Get memory regions
    auto regions = proc.queryRegions();

    // Filter regions
    std::vector<MemoryRegion> scanRegions;
    for (auto& r : regions) {
        if (r.state != MemState::Committed) continue;
        if (!(r.protection & MemProt::Read)) continue;
        if (r.base < config.startAddress) continue;
        if (r.base >= config.stopAddress) continue;
        if (config.scanWritableOnly && !(r.protection & MemProt::Write)) continue;
        if (config.scanExecutableOnly && !(r.protection & MemProt::Exec)) continue;
        if (!memoryTypeAllowed(config, r.type)) continue;
        scanRegions.push_back(r);
    }

    size_t valueSize = valueSizeFor(config.valueType);

    auto resultDir = makeScanDir();

    // Compute total and per-thread sizes
    int nThreads = std::min(threadCount_, std::max(1, (int)scanRegions.size()));
    size_t totalMem = 0;
    for (auto& r : scanRegions) totalMem += r.size;
    if (totalMem == 0) { ScanResult empty(resultDir / "results"); empty.finalize(); return empty; }
    size_t perThread = totalMem / nThreads;

    // Scan dispatch lambda (reused by each thread)
    auto scanRegion = [&](const uint8_t* buf, size_t bytesRead, uintptr_t base, ScanResult& res) {
        switch (config.valueType) {
            case ValueType::Byte:
                scanBuffer<uint8_t>(buf, bytesRead, base, config.alignment,
                    (uint8_t)config.intValue, (uint8_t)config.intValue2, getCompare<uint8_t>(config.compareType), res); break;
            case ValueType::Int16:
                scanBuffer<int16_t>(buf, bytesRead, base, config.alignment,
                    (int16_t)config.intValue, (int16_t)config.intValue2, getCompare<int16_t>(config.compareType), res); break;
            case ValueType::Int32:
                scanBuffer<int32_t>(buf, bytesRead, base, config.alignment,
                    (int32_t)config.intValue, (int32_t)config.intValue2, getCompare<int32_t>(config.compareType), res); break;
            case ValueType::Int64:
                scanBuffer<int64_t>(buf, bytesRead, base, config.alignment,
                    config.intValue, config.intValue2, getCompare<int64_t>(config.compareType), res); break;
            case ValueType::Float:
                scanBufferFloating<float>(buf, bytesRead, base, config.alignment, config, res); break;
            case ValueType::Double:
                scanBufferFloating<double>(buf, bytesRead, base, config.alignment, config, res); break;
            case ValueType::String:
                scanBufferString(buf, bytesRead, base, config.stringValue, res); break;
            case ValueType::UnicodeString:
                scanBufferUnicode(buf, bytesRead, base, config.stringValue, res); break;
            case ValueType::ByteArray:
                scanBufferAOB(buf, bytesRead, base, config.byteArray, config.byteArrayMask, res); break;
            case ValueType::Binary: {
                scanBufferBinary(buf, bytesRead, base, config.byteArray, config.byteMask, config.alignment, res);
                break;
            }
            case ValueType::All:
                scanBufferAllTypes(buf, bytesRead, base, config.alignment,
                    config.intValue, config.floatValue, config.compareType, res); break;
            default: break;
        }
    };

    // Assign region ranges to threads
    struct ThreadWork { size_t startIdx, endIdx; };
    std::vector<ThreadWork> work(nThreads);
    size_t rIdx = 0;
    for (int t = 0; t < nThreads; ++t) {
        work[t].startIdx = rIdx;
        size_t assigned = 0;
        while (rIdx < scanRegions.size() && (assigned < perThread || t == nThreads - 1)) {
            assigned += scanRegions[rIdx].size;
            ++rIdx;
        }
        work[t].endIdx = rIdx;
    }

    // Launch threads — each writes to its own ScanResult
    std::vector<ScanResult> threadResults;
    threadResults.reserve(nThreads);
    for (int t = 0; t < nThreads; ++t)
        threadResults.emplace_back(resultDir / ("t" + std::to_string(t)));

    std::atomic<size_t> scannedBytes{0};
    std::vector<std::thread> threads;

    for (int t = 0; t < nThreads; ++t) {
        threads.emplace_back([&, t]() {
            std::vector<uint8_t> buf;
            auto& res = threadResults[t];
            for (size_t ri = work[t].startIdx; ri < work[t].endIdx && !cancelled_.load(std::memory_order_relaxed); ++ri) {
                auto& region = scanRegions[ri];
                buf.resize(region.size);
                auto readResult = proc.read(region.base, buf.data(), region.size);
                if (!readResult || *readResult == 0) continue;
                size_t bytesRead = *readResult;
                scanRegion(buf.data(), bytesRead, region.base, res);
                scannedBytes.fetch_add(bytesRead, std::memory_order_relaxed);
                progress_.store((float)scannedBytes.load(std::memory_order_relaxed) / totalMem, std::memory_order_relaxed);
            }
            res.finalize();
        });
    }

    for (auto& t : threads) t.join();
    progress_.store(1.0f);

    // Merge by concatenating files (fast — no per-entry overhead)
    auto mergedDir = resultDir / "results";
    std::filesystem::create_directories(mergedDir);
    auto mergedAddrPath = mergedDir / "addresses.bin";
    auto mergedValPath = mergedDir / "values.bin";

    int madFd = open(mergedAddrPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    int mvdFd = open(mergedValPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    size_t totalCount = 0;

    constexpr size_t COPYBUF = 1024 * 1024; // 1MB copy buffer
    std::vector<uint8_t> copyBuf(COPYBUF);

    for (int t = 0; t < nThreads; ++t) {
        auto& tr = threadResults[t];
        totalCount += tr.count();

        // Concatenate addresses file
        auto tAddrPath = tr.directory() / "addresses.bin";
        int tfd = open(tAddrPath.c_str(), O_RDONLY);
        if (tfd >= 0) {
            ssize_t n;
            while ((n = ::read(tfd, copyBuf.data(), COPYBUF)) > 0)
                ::write(madFd, copyBuf.data(), n);
            close(tfd);
        }

        // Concatenate values file
        auto tValPath = tr.directory() / "values.bin";
        tfd = open(tValPath.c_str(), O_RDONLY);
        if (tfd >= 0) {
            ssize_t n;
            while ((n = ::read(tfd, copyBuf.data(), COPYBUF)) > 0)
                ::write(mvdFd, copyBuf.data(), n);
            close(tfd);
        }
    }
    close(madFd);
    close(mvdFd);

    // Cleanup per-thread dirs
    for (int t = 0; t < nThreads; ++t)
        std::filesystem::remove_all(resultDir / ("t" + std::to_string(t)));

    // Return merged result (reads existing files)
    return ScanResult(mergedDir);
}

ScanResult MemoryScanner::nextScan(ProcessHandle& proc, const ScanConfig& config, const ScanResult& previous) {
    cancelled_.store(false);
    progress_.store(0);

    if (config.valueType == ValueType::Custom)
        throw std::invalid_argument("ValueType::Custom requires a registered custom scanner");

    size_t valueSize = valueSizeForConfig(config);
    auto resultDir = makeScanDir();
    ScanResult result(resultDir / "results");

    size_t total = previous.count();
    size_t processed = 0;

    constexpr size_t BATCH = 4096;

    auto addrPath = previous.directory() / "addresses.bin";
    auto valPath  = previous.directory() / "values.bin";
    int afd = open(addrPath.c_str(), O_RDONLY);
    int vfd = open(valPath.c_str(), O_RDONLY);
    if (afd < 0 || vfd < 0) {
        if (afd >= 0) close(afd);
        if (vfd >= 0) close(vfd);
        result.finalize();
        return result;
    }

    std::vector<uintptr_t> addrs(BATCH);
    std::vector<uint8_t> oldVals(BATCH * valueSize);

    size_t remaining = total;
    while (remaining > 0 && !cancelled_.load()) {
        size_t n = std::min(remaining, BATCH);
        ::read(afd, addrs.data(), n * sizeof(uintptr_t));
        ::read(vfd, oldVals.data(), n * valueSize);

        for (size_t i = 0; i < n; ++i) {
            // Read current value
            std::vector<uint8_t> currentVal(valueSize);
            auto rr = proc.read(addrs[i], currentVal.data(), valueSize);
            if (!rr || *rr < valueSize) continue;

            uint8_t* oldVal = oldVals.data() + i * valueSize;
            bool match = false;

            // Compare based on type
            switch (config.valueType) {
                case ValueType::Byte:
                    match = compareNextNumeric<uint8_t>(config, currentVal.data(), oldVal);
                    break;
                case ValueType::Int16:
                    match = compareNextNumeric<int16_t>(config, currentVal.data(), oldVal);
                    break;
                case ValueType::Int32: {
                    match = compareNextNumeric<int32_t>(config, currentVal.data(), oldVal);
                    break;
                }
                case ValueType::Int64:
                    match = compareNextNumeric<int64_t>(config, currentVal.data(), oldVal);
                    break;
                case ValueType::Float: {
                    match = compareNextNumeric<float>(config, currentVal.data(), oldVal);
                    break;
                }
                case ValueType::Double:
                    match = compareNextNumeric<double>(config, currentVal.data(), oldVal);
                    break;
                case ValueType::String: {
                    if (config.compareType >= ScanCompare::Changed) {
                        match = (std::memcmp(currentVal.data(), oldVal, valueSize) != 0) ==
                                (config.compareType == ScanCompare::Changed ||
                                 config.compareType == ScanCompare::Increased ||
                                 config.compareType == ScanCompare::Decreased);
                    } else if (config.compareType == ScanCompare::Exact) {
                        match = config.stringValue.size() == valueSize &&
                                std::memcmp(currentVal.data(), config.stringValue.data(), valueSize) == 0;
                    } else if (config.compareType == ScanCompare::Unknown) {
                        match = true;
                    }
                    break;
                }
                case ValueType::UnicodeString: {
                    auto needle = utf16LeBytes(config.stringValue);
                    if (config.compareType >= ScanCompare::Changed) {
                        match = (std::memcmp(currentVal.data(), oldVal, valueSize) != 0) ==
                                (config.compareType == ScanCompare::Changed ||
                                 config.compareType == ScanCompare::Increased ||
                                 config.compareType == ScanCompare::Decreased);
                    } else if (config.compareType == ScanCompare::Exact) {
                        match = needle.size() == valueSize &&
                                std::memcmp(currentVal.data(), needle.data(), valueSize) == 0;
                    } else if (config.compareType == ScanCompare::Unknown) {
                        match = true;
                    }
                    break;
                }
                case ValueType::ByteArray:
                    if (config.compareType >= ScanCompare::Changed) {
                        match = (std::memcmp(currentVal.data(), oldVal, valueSize) != 0) ==
                                (config.compareType == ScanCompare::Changed ||
                                 config.compareType == ScanCompare::Increased ||
                                 config.compareType == ScanCompare::Decreased);
                    } else if (config.compareType == ScanCompare::Exact) {
                        match = compareMaskedBytes(currentVal.data(), config.byteArray, config.byteArrayMask);
                    } else if (config.compareType == ScanCompare::Unknown) {
                        match = true;
                    }
                    break;
                case ValueType::Binary:
                    if (config.compareType >= ScanCompare::Changed) {
                        match = (std::memcmp(currentVal.data(), oldVal, valueSize) != 0) ==
                                (config.compareType == ScanCompare::Changed ||
                                 config.compareType == ScanCompare::Increased ||
                                 config.compareType == ScanCompare::Decreased);
                    } else if (config.compareType == ScanCompare::Exact) {
                        match = config.byteMask.size() == config.byteArray.size();
                        for (size_t j = 0; match && j < valueSize; ++j) {
                            if ((currentVal[j] & config.byteMask[j]) !=
                                (config.byteArray[j] & config.byteMask[j])) {
                                match = false;
                            }
                        }
                    } else if (config.compareType == ScanCompare::Unknown) {
                        match = true;
                    }
                    break;
                default: {
                    // Generic byte comparison
                    match = (std::memcmp(currentVal.data(), oldVal, valueSize) != 0) ==
                            (config.compareType == ScanCompare::Changed);
                    break;
                }
            }

            if (match)
                result.addResult(addrs[i], currentVal.data(), valueSize);
        }

        processed += n;
        remaining -= n;
        progress_.store((float)processed / total);
    }

    close(afd);
    close(vfd);
    result.finalize();
    return result;
}

} // namespace ce
