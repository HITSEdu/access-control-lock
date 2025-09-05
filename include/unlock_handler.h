#ifndef UNLOCK_HANDLER_H
#define UNLOCK_HANDLER_H

#include <string>
#include <memory>
#include <vector>
#include <cstdint>
#include "hasher.h"

class UnlockHandler {
public:
    UnlockHandler(const std::vector<uint8_t>& secret_key, uint64_t time_tolerance_ms);
    std::string handleRequest(const std::string& hash_hex, const std::string& timestamp_ms = "");
    
private:
    std::unique_ptr<Hasher> hasher_;
    bool validateInput(const std::string& hash_hex, const std::string& timestamp_ms) const;
};

#endif 