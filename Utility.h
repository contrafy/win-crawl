/*
* Ahmad Raaiyan
* CSCE 463 - 500
* Fall '24
* hw1p3/Utility.h
*/

#ifndef UTILITY_H
#define UTILITY_H

#include <string>

bool parseURL(const std::string& url, std::string& scheme, std::string& host, int& port, std::string& request);

#endif // UTILITY_H
