#include <cstdint>
#include <iostream>
#include <vector>

#include "../include/hasher.h"
#include "../include/http_server.h"
#include "../include/request_parser.h"
#include "../include/unlock_handler.h"


int main() {    
    std::vector<uint8_t> secret_key = Hasher::generate_random_key(32);
    uint64_t time_tolerance_ms = 1000;  
    HttpServer server(secret_key, time_tolerance_ms);
     UnlockHandler unlockHandler(secret_key, time_tolerance_ms);

server.addRoute(
        "/unlock", [&unlockHandler](const std::string& hash_hex,
                                    const std::string& timestamp_ms) {
            return unlockHandler.handleRequest(hash_hex, timestamp_ms);
        });

    std::cout << "HTTP Server started with secret key: "
              << Hasher::bytes_to_hex(secret_key) << std::endl;
    std::cout << "Time tolerance: " << time_tolerance_ms << "ms" << std::endl;


    Hasher test_hasher(secret_key, time_tolerance_ms);
    std::vector<uint8_t> test_hash = test_hasher.compute_time_hash(32);
    std::string test_hash_hex = Hasher::bytes_to_hex(test_hash);

    std::cout << "Test hash: " << test_hash_hex << std::endl;

    std::string response = server.handleRequest("/unlock", test_hash_hex, "");
    std::cout << "Valid request response: " << response << std::endl;


    std::string invalid_response =
        server.handleRequest("/unlock", "invalidhash123", "");
    std::cout << "Invalid request response: " << invalid_response << std::endl;

    Hasher::secure_erase(secret_key);

    return 0;
}