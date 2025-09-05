#include "../include/unlock_handler.h"
#include "../include/hasher.h"
#include <ctime>
#include <chrono>
#include <sstream>
#include <iostream>
#include <stdexcept>

UnlockHandler::UnlockHandler(const std::vector<uint8_t>& secret_key, uint64_t time_tolerance_ms) {
    hasher_ = std::make_unique<Hasher>(secret_key, time_tolerance_ms);
}

std::string UnlockHandler::handleRequest(const std::string& hash_hex, const std::string& timestamp_ms) {
    if (!validateInput(hash_hex, timestamp_ms)) {
        return "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n"
               "{\"status\":\"error\",\"message\":\"Invalid input parameters\"}";
    }
    
    try {
        std::vector<uint8_t> expected_hash = Hasher::hex_to_bytes(hash_hex);
        
        if (!timestamp_ms.empty()) {
            uint64_t timestamp = std::stoull(timestamp_ms);
            Hasher temp_hasher(hasher_->generate_random_key(32), hasher_->);
            
            return "HTTP/1.1 501 Not Implemented\r\nContent-Type: application/json\r\n\r\n"
                   "{\"status\":\"error\",\"message\":\"Timestamp-based verification not implemented\"}";
        }
        
        bool isValid = hasher_->verify_time_hash(expected_hash, 5000);
        
        Hasher::secure_erase(expected_hash);
        
        if (isValid) {
            return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                   "{\"status\":\"success\",\"message\":\"Access granted\"}";
        } else {
            return "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n"
                   "{\"status\":\"error\",\"message\":\"Invalid hash or expired\"}";
        }
    } catch (const std::exception& e) {
        return "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n"
               "{\"status\":\"error\",\"message\":\"Server error: " + std::string(e.what()) + "\"}";
    }
}

bool UnlockHandler::validateInput(const std::string& hash_hex, const std::string& timestamp_ms) const {
    if (hash_hex.empty() || hash_hex.length() % 2 != 0) {
        return false;
    }
    
    for (char c : hash_hex) {
        if (!std::isxdigit(c)) {
            return false;
        }
    }

    if (!timestamp_ms.empty()) {
        try {
            uint64_t ts = std::stoull(timestamp_ms);

            auto now = std::chrono::system_clock::now().time_since_epoch();
            auto currentTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
            
            if (ts > currentTimestamp + 3600000) {
                return false;
            }
        } catch (...) {
            return false;
        }
    }
    
    return true;
}