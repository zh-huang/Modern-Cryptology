#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <NTL/ZZ_p.h>
#define SHA1ROTATELEFT(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

NTL_CLIENT

using namespace std;

class SHA_1
{
    vector<uint32_t> h{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
    void processChunk(vector<uint32_t> &h, const string &chunk);

public:
    string sha1(const string &input);
    ZZ sha1zz(const string &input);
};