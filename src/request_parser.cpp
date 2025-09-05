#include "../include/request_parser.h"
#include <sstream>
#include <algorithm>
#include <cctype>

std::unordered_map<std::string, std::string> RequestParser::parseQueryParams(const std::string& query) {
    std::unordered_map<std::string, std::string> params;
    std::istringstream iss(query);
    std::string pair;
    
    while (std::getline(iss, pair, '&')) {
        size_t pos = pair.find('=');
        if (pos != std::string::npos) {
            std::string key = pair.substr(0, pos);
            std::string value = pair.substr(pos + 1);
            params[key] = value;
        }
    }
    
    return params;
}

std::string RequestParser::getParam(const std::unordered_map<std::string, std::string>& params, 
                                  const std::string& key, 
                                  const std::string& defaultValue) {
    auto it = params.find(key);
    if (it != params.end()) {
        return it->second;
    }
    return defaultValue;
}