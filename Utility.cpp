#include "Utility.h"

#include <cctype>

// Parses http://host[:port][/path][?query][#fragment]. The fragment is dropped,
// the host is lowercased, and an absent path becomes "/".
bool parseURL(const std::string& url, std::string& scheme, std::string& host, int& port, std::string& request) {
    const std::string prefix = "http://";
    if (url.size() <= prefix.size()) {
        return false;
    }
    for (size_t i = 0; i < prefix.size(); i++) {
        if (std::tolower(static_cast<unsigned char>(url[i])) != prefix[i]) {
            return false;
        }
    }
    scheme = "http";

    size_t end = url.find('#', prefix.size());
    if (end == std::string::npos) {
        end = url.size();
    }

    size_t hostEnd = url.find_first_of(":/?", prefix.size());
    if (hostEnd == std::string::npos || hostEnd > end) {
        hostEnd = end;
    }
    if (hostEnd == prefix.size()) {
        return false;
    }
    host.assign(url, prefix.size(), hostEnd - prefix.size());
    for (char& c : host) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    size_t pos = hostEnd;
    port = 80;
    if (pos < end && url[pos] == ':') {
        size_t portEnd = url.find_first_of("/?", pos + 1);
        if (portEnd == std::string::npos || portEnd > end) {
            portEnd = end;
        }
        if (portEnd == pos + 1 || portEnd - pos - 1 > 5) {
            return false;
        }
        port = 0;
        for (size_t i = pos + 1; i < portEnd; i++) {
            if (!std::isdigit(static_cast<unsigned char>(url[i]))) {
                return false;
            }
            port = port * 10 + (url[i] - '0');
        }
        if (port <= 0 || port > 65535) {
            return false;
        }
        pos = portEnd;
    }

    request.clear();
    if (pos == end || url[pos] != '/') {
        request = "/";
    }
    request.append(url, pos, end - pos);
    return true;
}
