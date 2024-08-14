#include "sha1.h"
#include "common.h"

void SHA_1::processChunk(vector<uint32_t> &h, const string &chunk)
{
    vector<uint32_t> w(80, 0);
    for (int i = 0; i < 16; ++i)
    {
        w[i] = (chunk[i * 4] & 0xff) << 24 |
               (chunk[i * 4 + 1] & 0xff) << 16 |
               (chunk[i * 4 + 2] & 0xff) << 8 |
               (chunk[i * 4 + 3] & 0xff);
    }
    for (int i = 16; i < 80; ++i)
        w[i] = SHA1ROTATELEFT((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1);
    uint32_t a = h[0];
    uint32_t b = h[1];
    uint32_t c = h[2];
    uint32_t d = h[3];
    uint32_t e = h[4];

    for (int i = 0; i < 80; ++i)
    {
        uint32_t f, k;
        if (i < 20)
        {
            f = (b & c) | ((~b) & d);
            k = 0x5a827999;
        }
        else if (i < 40)
        {
            f = b ^ c ^ d;
            k = 0x6ed9eba1;
        }
        else if (i < 60)
        {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdc;
        }
        else
        {
            f = b ^ c ^ d;
            k = 0xca62c1d6;
        }
        uint32_t temp = SHA1ROTATELEFT(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = SHA1ROTATELEFT(b, 30);
        b = a;
        a = temp;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

string SHA_1::sha1(const string &input)
{
    string padded_input = input;
    uint64_t orig_length = input.length() * 8;
    padded_input += (char)0x80;
    while (padded_input.length() % 64 != 56)
        padded_input += (char)0x00;
    for (int i = 7; i >= 0; --i)
        padded_input += (char)((orig_length >> (i * 8)) & 0xff);
    for (size_t i = 0; i < padded_input.length(); i += 64)
        processChunk(h, padded_input.substr(i, 64));
    string result;
    for (size_t i = 0; i < h.size(); ++i)
        for (int j = 7; j >= 0; --j)
            result += toHex(((h[i] >> (j * 4)) & 0xf));
    return result;
}

ZZ SHA_1::sha1zz(const string &input)
{
    string padded_input = input;
    uint64_t orig_length = input.length() * 8;
    padded_input += (char)0x80;
    while (padded_input.length() % 64 != 56)
        padded_input += (char)0x00;
    for (int i = 7; i >= 0; --i)
        padded_input += (char)((orig_length >> (i * 8)) & 0xff);
    for (size_t i = 0; i < padded_input.length(); i += 64)
        processChunk(h, padded_input.substr(i, 64));
    ZZ result = conv<ZZ>("0");
    for (size_t i = h.size() - 1; i < h.size(); --i)
        for (int j = 0; j < 8; ++j)
            result = result * 16 + ((h[i] >> (j * 4)) & 0xf);
    return result;
}