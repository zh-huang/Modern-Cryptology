#pragma once
#include <sstream>
#include <vector>

using namespace std;

char toHex(const uint8_t i);

stringstream printHex(const vector<uint8_t> &text);

bool readHex(istream &in, uint8_t &t);