#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <string>
#include <functional>
#include <unordered_map>
#include <vector>
#include <cstdint>

class HttpServer {
public:
    using Handler = std::function<std::string(const std::string&, const std::string&)>;
    
    HttpServer(const std::vector<uint8_t>& secret_key, uint64_t time_tolerance_ms);
    void addRoute(const std::string& path, Handler handler);
    std::string handleRequest(const std::string& path, 
                             const std::string& hash_hex, 
                             const std::string& timestamp_ms = "") const;
    
private:
    std::unordered_map<std::string, Handler> routes_;
    std::vector<uint8_t> secret_key_;
    uint64_t time_tolerance_ms_;
};

#endif 