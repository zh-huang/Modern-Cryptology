#include "common.h"

char toHex(const uint8_t i)
{
    if (i % 16 < 10)
        return '0' + i % 16;
    return i % 16 - 10 + 'A';
}

stringstream printHex(const vector<uint8_t> &text)
{
    stringstream ss;
    for (uint32_t count = 0; count < text.size(); ++count)
    {
        if (count % 16 == 8)
            ss << ' ';
        else if (count != 0 && count % 16 == 0)
            ss << endl;
        ss << toHex(text[count] / 16) << toHex(text[count] % 16);
    }
    return ss;
}

bool readHex(istream &in, uint8_t &t)
{
    int k;
    t = 0;
    for (int times = 0; times < 2; ++times)
    {
        while (1)
        {
            k = in.get();
            if (k == EOF)
                return false;
            else if (k <= '9' && k >= '0')
                t = t * 16 + k - '0';
            else if (k <= 'f' && k >= 'a')
                t = t * 16 + k - 'a' + 10;
            else if (k <= 'F' && k >= 'A')
                t = t * 16 + k - 'A' + 10;
            else
                continue;
            break;
        }
    }
    return true;
}