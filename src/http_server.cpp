#include "../include/http_server.h"
#include "../include/unlock_handler.h"
#include <iostream>

HttpServer::HttpServer(const std::vector<uint8_t>& secret_key, uint64_t time_tolerance_ms) 
    : secret_key_(secret_key), time_tolerance_ms_(time_tolerance_ms) {}

void HttpServer::addRoute(const std::string& path, Handler handler) {
    routes_[path] = handler;
}

std::string HttpServer::handleRequest(const std::string& path, 
                                    const std::string& hash_hex, 
                                    const std::string& timestamp_ms) const {
    auto it = routes_.find(path);
    if (it != routes_.end()) {
        return it->second(hash_hex, timestamp_ms);
    }
    
    return "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n"
           "{\"status\":\"error\",\"message\":\"Route not found\"}";
}