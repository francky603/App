/**
 * @file crypto_utils.cpp
 * @brief Implémentation des utilitaires cryptographiques
 */

#include "crypto_utils.h"
#include <cstring>
#include <algorithm>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <iostream>

#ifdef _WIN32
    #include <windows.h>
    #include <wincrypt.h>
#else
    #include <fstream>
#endif

namespace mixnet {
namespace utils {

// ============================================================================
// SecureRandom Implementation
// ============================================================================

void SecureRandom::generate_bytes(uint8_t* buffer, size_t length) {
#ifdef _WIN32
    HCRYPTPROV hProv;
    if (CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, 
                            CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        CryptGenRandom(hProv, static_cast<DWORD>(length), buffer);
        CryptReleaseContext(hProv, 0);
    } else {
        // Fallback to rand() (not secure, but works for demo)
        for (size_t i = 0; i < length; ++i) {
            buffer[i] = static_cast<uint8_t>(std::rand() % 256);
        }
    }
#else
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (urandom && urandom.read(reinterpret_cast<char*>(buffer), length)) {
        return;
    }
    
    // Fallback
    for (size_t i = 0; i < length; ++i) {
        buffer[i] = static_cast<uint8_t>(std::rand() % 256);
    }
#endif
}

std::vector<uint8_t> SecureRandom::generate_vector(size_t length) {
    std::vector<uint8_t> result(length);
    generate_bytes(result.data(), length);
    return result;
}

uint64_t SecureRandom::random_range(uint64_t min, uint64_t max) {
    if (min >= max) return min;
    
    uint64_t range = max - min + 1;
    std::vector<uint8_t> random_bytes = generate_vector(8);
    
    uint64_t random_value = 0;
    for (int i = 0; i < 8; ++i) {
        random_value |= (static_cast<uint64_t>(random_bytes[i]) << (i * 8));
    }
    
    return min + (random_value % range);
}

// ============================================================================
// SHA256 Implementation (Simple implementation for demonstration)
// Note: In production, use OpenSSL or a dedicated crypto library
// ============================================================================

namespace {
    // Constants for SHA256
    constexpr uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    
    inline uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }
    
    inline uint32_t choose(uint32_t e, uint32_t f, uint32_t g) {
        return (e & f) ^ (~e & g);
    }
    
    inline uint32_t majority(uint32_t a, uint32_t b, uint32_t c) {
        return (a & b) ^ (a & c) ^ (b & c);
    }
    
    inline uint32_t sig0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }
    
    inline uint32_t sig1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }
    
    inline uint32_t theta0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }
    
    inline uint32_t theta1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }
}

std::array<uint8_t, 32> SHA256::hash(const uint8_t* data, size_t length) {
    // Initial hash values
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    // Pre-processing: adding padding bits
    size_t original_bit_length = length * 8;
    size_t padded_length = ((length + 8) / 64 + 1) * 64;
    
    std::vector<uint8_t> padded_data(padded_length, 0);
    std::memcpy(padded_data.data(), data, length);
    padded_data[length] = 0x80;
    
    // Append original length in bits as big-endian
    for (int i = 0; i < 8; ++i) {
        padded_data[padded_length - 1 - i] = static_cast<uint8_t>(original_bit_length >> (i * 8));
    }
    
    // Process each 512-bit chunk
    for (size_t chunk = 0; chunk < padded_length; chunk += 64) {
        uint32_t w[64];
        
        // Copy chunk into first 16 words
        for (int i = 0; i < 16; ++i) {
            w[i] = (padded_data[chunk + i * 4] << 24) |
                   (padded_data[chunk + i * 4 + 1] << 16) |
                   (padded_data[chunk + i * 4 + 2] << 8) |
                   (padded_data[chunk + i * 4 + 3]);
        }
        
        // Extend the sixteen 32-bit words into sixty-four 32-bit words
        for (int i = 16; i < 64; ++i) {
            w[i] = theta1(w[i - 2]) + w[i - 7] + theta0(w[i - 15]) + w[i - 16];
        }
        
        // Initialize working variables
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        
        // Main loop
        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = hh + sig1(e) + choose(e, f, g) + K[i] + w[i];
            uint32_t t2 = sig0(a) + majority(a, b, c);
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        
        // Add compressed chunk to current hash value
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    
    // Produce the final hash value (big-endian)
    std::array<uint8_t, 32> hash;
    int idx = 0;
    for (int i = 0; i < 8; ++i) {
        hash[idx++] = (h[i] >> 24) & 0xFF;
        hash[idx++] = (h[i] >> 16) & 0xFF;
        hash[idx++] = (h[i] >> 8) & 0xFF;
        hash[idx++] = h[i] & 0xFF;
    }
    
    return hash;
}

std::array<uint8_t, 32> SHA256::hash(const std::vector<uint8_t>& data) {
    return hash(data.data(), data.size());
}

std::array<uint8_t, 32> SHA256::hash(const std::string& text) {
    return hash(reinterpret_cast<const uint8_t*>(text.data()), text.size());
}

std::string SHA256::hash_hex(const std::vector<uint8_t>& data) {
    auto hash_result = hash(data);
    return HexEncoder::encode(hash_result.data(), hash_result.size());
}

std::string SHA256::hash_hex(const std::string& text) {
    auto hash_result = hash(text);
    return HexEncoder::encode(hash_result.data(), hash_result.size());
}

// ============================================================================
// HexEncoder Implementation
// ============================================================================

std::string HexEncoder::encode(const uint8_t* data, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::string HexEncoder::encode(const std::vector<uint8_t>& data) {
    return encode(data.data(), data.size());
}

std::vector<uint8_t> HexEncoder::decode(const std::string& hex) {
    std::vector<uint8_t> result;
    if (hex.length() % 2 != 0) return result;
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16));
        result.push_back(byte);
    }
    
    return result;
}

// ============================================================================
// Base64 Implementation
// ============================================================================

static const char BASE64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Base64::encode(const uint8_t* data, size_t length) {
    std::string result;
    int val = 0, valb = -6;
    
    for (size_t i = 0; i < length; i++) {
        val = (val << 8) + data[i];
        valb += 8;
        while (valb >= 0) {
            result.push_back(BASE64_CHARS[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    
    if (valb > -6) {
        result.push_back(BASE64_CHARS[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    
    while (result.size() % 4) {
        result.push_back('=');
    }
    
    return result;
}

std::string Base64::encode(const std::vector<uint8_t>& data) {
    return encode(data.data(), data.size());
}

std::vector<uint8_t> Base64::decode(const std::string& base64) {
    std::vector<uint8_t> result;
    std::vector<int> T(256, -1);
    
    for (int i = 0; i < 64; i++) {
        T[BASE64_CHARS[i]] = i;
    }
    
    int val = 0, valb = -8;
    for (char c : base64) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            result.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    
    return result;
}

// ============================================================================
// Time Utilities
// ============================================================================

std::string format_timestamp(uint64_t timestamp_ms) {
    time_t seconds = timestamp_ms / 1000;
    struct tm* tm_info = localtime(&seconds);
    
    char buffer[64];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    
    return std::string(buffer);
}

// ============================================================================
// Constant-time Comparison
// ============================================================================

bool constant_time_compare(const uint8_t* a, const uint8_t* b, size_t length) {
    volatile uint8_t result = 0;
    for (size_t i = 0; i < length; ++i) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

bool constant_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    return constant_time_compare(a.data(), b.data(), a.size());
}

bool verify_auth_tag(const crypto::AuthTag& expected, const crypto::AuthTag& received) {
    return constant_time_compare(expected.data.data(), received.data.data(), 16);
}

// ============================================================================
// Serialization
// ============================================================================

std::vector<uint8_t> serialize_uint64(uint64_t value) {
    std::vector<uint8_t> result(8);
    for (int i = 0; i < 8; ++i) {
        result[i] = (value >> (i * 8)) & 0xFF;
    }
    return result;
}

uint64_t deserialize_uint64(const uint8_t* data, size_t offset) {
    uint64_t result = 0;
    for (int i = 0; i < 8; ++i) {
        result |= (static_cast<uint64_t>(data[offset + i]) << (i * 8));
    }
    return result;
}

std::vector<uint8_t> concat_buffers(const std::vector<std::vector<uint8_t>>& buffers) {
    size_t total_size = 0;
    for (const auto& buf : buffers) {
        total_size += buf.size();
    }
    
    std::vector<uint8_t> result;
    result.reserve(total_size);
    
    for (const auto& buf : buffers) {
        result.insert(result.end(), buf.begin(), buf.end());
    }
    
    return result;
}

std::vector<uint8_t> concat_buffers(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    std::vector<uint8_t> result;
    result.reserve(a.size() + b.size());
    result.insert(result.end(), a.begin(), a.end());
    result.insert(result.end(), b.begin(), b.end());
    return result;
}

// ============================================================================
// Debug Utilities
// ============================================================================

std::string dump_hex(const uint8_t* data, size_t length, size_t max_bytes) {
    size_t display_length = std::min(length, max_bytes);
    std::string result = HexEncoder::encode(data, display_length);
    
    if (length > max_bytes) {
        result += "... (" + std::to_string(length) + " bytes total)";
    }
    
    return result;
}

std::string dump_hex(const std::vector<uint8_t>& data, size_t max_bytes) {
    return dump_hex(data.data(), data.size(), max_bytes);
}

void print_suite_info(const crypto::SuiteInfo& info) {
    std::cout << "Suite: " << info.name << std::endl;
    std::cout << "  Key Exchange: " << info.key_exchange << std::endl;
    std::cout << "  Symmetric Cipher: " << info.symmetric_cipher << std::endl;
    std::cout << "  Post-Quantum: " << (info.has_pqc ? "Yes" : "No") << std::endl;
    std::cout << "  Forward Secrecy: " << (info.has_forward_secrecy ? "Yes" : "No") << std::endl;
    std::cout << "  Performance Score: " << (info.performance_score * 100) << "%" << std::endl;
    std::cout << "  Security Score: " << (info.security_score * 100) << "%" << std::endl;
}

} // namespace utils
} // namespace mixnet
