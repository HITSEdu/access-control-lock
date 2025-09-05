#include "../include/hasher.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>

Hasher::Hasher(const std::vector<uint8_t>& secret_key,
               uint64_t time_tolerance_ms)
    : secret_key_(secret_key), time_tolerance_ms_(time_tolerance_ms) {
    if (secret_key_.empty()) {
        throw std::invalid_argument("Secret key cannot be empty");
    }
}

Hasher::~Hasher() {
    secure_erase(secret_key_);
}

std::vector<uint8_t> Hasher::compute_time_hash(size_t output_length) {
    uint64_t time_slot = get_current_time_slot();
    std::vector<uint8_t> time_data = uint64_to_bytes(time_slot);
    auto result = compute_hmac_sha256(time_data, output_length);
    secure_erase(time_data);
    return result;
}

bool Hasher::verify_time_hash(const std::vector<uint8_t>& expected_hash, 
                             uint64_t max_time_drift_ms) {
    uint64_t current_time = get_current_time_ms();

    for (uint64_t time_offset = 0; time_offset <= max_time_drift_ms;
         time_offset += time_tolerance_ms_) {
        uint64_t test_time_past = current_time - time_offset;
        uint64_t time_slot_past = test_time_past / time_tolerance_ms_;

        std::vector<uint8_t> time_data_past = uint64_to_bytes(time_slot_past);
        std::vector<uint8_t> hash_past =
            compute_hmac_sha256(time_data_past, expected_hash.size());

        if (hash_past == expected_hash) {
            secure_erase(time_data_past);
            secure_erase(hash_past);
            return true;
        }

        secure_erase(time_data_past);
        secure_erase(hash_past);

        if (time_offset > 0) {
            uint64_t test_time_future = current_time + time_offset;
            uint64_t time_slot_future = test_time_future / time_tolerance_ms_;

            std::vector<uint8_t> time_data_future =
                uint64_to_bytes(time_slot_future);
            std::vector<uint8_t> hash_future =
                compute_hmac_sha256(time_data_future, expected_hash.size());

            if (hash_future == expected_hash) {
                secure_erase(time_data_future);
                secure_erase(hash_future);
                return true;
            }

            secure_erase(time_data_future);
            secure_erase(hash_future);
        }
    }

    return false;
}

std::vector<uint8_t> Hasher::generate_random_key(size_t length) {
    std::vector<uint8_t> key(length);
    if (RAND_bytes(key.data(), static_cast<int>(length)) != 1) {
        throw std::runtime_error("Failed to generate random key");
    }
    return key;
}

std::string Hasher::bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<uint8_t> Hasher::hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte =
            static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

void Hasher::secure_erase(std::vector<uint8_t>& data) {
    if (!data.empty()) {
        memset(data.data(), 0, data.size());
        data.clear();
    }
}

void Hasher::secure_erase(std::string& data) {
    if (!data.empty()) {
        memset(&data[0], 0, data.size());
        data.clear();
    }
}

uint64_t Hasher::get_current_time_ms() const {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration)
        .count();
}

uint64_t Hasher::get_current_time_slot() const {
    uint64_t current_time_ms = get_current_time_ms();
    return current_time_ms / time_tolerance_ms_;
}

std::vector<uint8_t> Hasher::uint64_to_bytes(uint64_t value) const {
    std::vector<uint8_t> bytes(8);
    for (int i = 0; i < 8; ++i) {
        bytes[i] = static_cast<uint8_t>(value >> (i * 8));
    }
    return bytes;
}

std::vector<uint8_t> Hasher::compute_hmac_sha256(
    const std::vector<uint8_t>& data, size_t output_length) const {
    std::vector<uint8_t> result(EVP_MAX_MD_SIZE);
    unsigned int result_len = 0;

    const unsigned char* hmac_result = HMAC(
        EVP_sha256(), secret_key_.data(), static_cast<int>(secret_key_.size()),
        data.data(), data.size(), result.data(), &result_len);

    if (hmac_result == nullptr) {
        throw std::runtime_error("HMAC computation failed");
    }

    result.resize(std::min(output_length, static_cast<size_t>(result_len)));
    return result;
}