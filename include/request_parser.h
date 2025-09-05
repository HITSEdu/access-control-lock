#ifndef REQUEST_PARSER_H
#define REQUEST_PARSER_H

#include <string>
#include <unordered_map>

class RequestParser {
   public:
    static std::unordered_map<std::string, std::string> parseQueryParams(
        const std::string& query);
    static std::string getParam(
        const std::unordered_map<std::string, std::string>& params,
        const std::string& key, const std::string& defaultValue = "");
};

#endif