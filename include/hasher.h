#ifndef HASH_H
#define HASH_H

#include <vector>
#include <string>
#include <cstdint>

class Hasher {
public:
    Hasher(const std::vector<uint8_t>& secret_key, uint64_t time_tolerance_ms);
    ~Hasher();

    std::vector<uint8_t> compute_time_hash(size_t output_length);

    bool verify_time_hash(const std::vector<uint8_t>& expected_hash, 
                         uint64_t max_time_drift_ms);

    static std::vector<uint8_t> generate_random_key(size_t length);

    static std::string bytes_to_hex(const std::vector<uint8_t>& bytes);

    static std::vector<uint8_t> hex_to_bytes(const std::string& hex);

    static void secure_erase(std::vector<uint8_t>& data);

    static void secure_erase(std::string& data);

private:
    std::vector<uint8_t> secret_key_;
    uint64_t time_tolerance_ms_;

    uint64_t get_current_time_ms() const;

    uint64_t get_current_time_slot() const;

    std::vector<uint8_t> uint64_to_bytes(uint64_t value) const;

    std::vector<uint8_t> compute_hmac_sha256(const std::vector<uint8_t>& data, 
                                            size_t output_length) const;
};

#endif