#include "Utility.h"

#include <regex>
#include <iostream>

bool parseURL(const std::string& url, std::string& scheme, std::string& host, int& port, std::string& request) {
    // port and path are marked as optional so the regex_match() is only checking for http://baseurl basically
    std::regex urlRegex(R"(^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/:]+)(?::(\d+))?(?:(/.*)?)?)");
    std::smatch matches;

    if (std::regex_match(url, matches, urlRegex)) {
        if ((scheme = matches[1].str()) != "http") {
            // printf("failed with invalid scheme\n");
            return false;
        }
        host = matches[2].str();

        // extract the port if one exists
        // default to 80 otherwise
        if (matches[3].matched) {
            std::string portStr = matches[3].str();

            try {
                // will go to catch block if there are no numbers
                port = std::stoi(portStr);

                // check if port is invalid (0 or not in valid range)
                if (port <= 0 || port > 65535) {
                    // printf("failed with invalid port\n");
                    return false;
                }
            }
            catch (const std::invalid_argument& e) {
                // printf("failed with invalid port\n");
                return false;
            }
        }
        else {
            port = 80;
        }

        //path default to /
        request = matches[4].length() > 0 ? matches[4].str() : "/";
        return true;
    }

    //uh oh
    // printf("failed with invalid URL\n");
    return false;
}
