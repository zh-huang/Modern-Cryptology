#include "aes128.h"

void AES_128::subBytes(vector<uint8_t> &word)
{
    for (auto &byte : word)
        byte = sBox[byte];
}

void AES_128::invSubBytes(vector<uint8_t> &word)
{
    for (auto &byte : word)
        byte = invSBox[byte];
}

void AES_128::rotWord(vector<uint8_t> &word)
{
    swap(word[0], word[1]);
    swap(word[1], word[2]);
    swap(word[2], word[3]);
}

vector<uint8_t> AES_128::keyExpansion(const vector<uint8_t> &key)
{

    vector<uint8_t> w(176);
    // Copy the first 4 groups
    for (int i = 0; i < 16; ++i)
        w[i] = key[i];
    for (int i = 4; i < 44; ++i)
    {
        vector<uint8_t> temp = {w[4 * i - 4], w[4 * i - 3], w[4 * i - 2], w[4 * i - 1]};
        if (i % Nk == 0)
        {
            rotWord(temp);
            subBytes(temp);
            temp[0] ^= Rcon[i / Nk];
        }
        w[4 * i + 0] = w[4 * (i - Nk) + 0] ^ temp[0];
        w[4 * i + 1] = w[4 * (i - Nk) + 1] ^ temp[1];
        w[4 * i + 2] = w[4 * (i - Nk) + 2] ^ temp[2];
        w[4 * i + 3] = w[4 * (i - Nk) + 3] ^ temp[3];
    }
    return w;
}

void AES_128::addRoundKey(const vector<uint8_t> expandedKey, const int round, vector<uint8_t> &word)
{
    for (int i = 0; i < 16; ++i)
        word[i] ^= expandedKey[(round * 16) + i];
}

void AES_128::shiftRows(vector<uint8_t> &word)
{
    vector<uint8_t> tmp = {word[0], word[5], word[10], word[15],
                           word[4], word[9], word[14], word[3],
                           word[8], word[13], word[2], word[7],
                           word[12], word[1], word[6], word[11]};
    word = tmp;
}
void AES_128::invShiftRows(vector<uint8_t> &word)
{
    vector<uint8_t> tmp = {word[0], word[13], word[10], word[7],
                           word[4], word[1], word[14], word[11],
                           word[8], word[5], word[2], word[15],
                           word[12], word[9], word[6], word[3]};
    word = tmp;
}

uint8_t AES_128::gmul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int counter = 0; counter < 8; counter++)
    {
        if (b & 1)
            p ^= a;
        bool hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set)
            a ^= 0x1B;
        b >>= 1;
    }
    return p;
}
// The quick algorithm showed in ppt
void AES_128::mixColumns(vector<uint8_t> &word)
{
    vector<uint8_t> tmp(4);
    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
            tmp[j] = word[i * 4 + j];
        // s(i,j) xor s(i,j) is zeros
        for (int j = 0; j < 4; ++j)
            for (int k = 0; k < 4; ++k)
                word[i * 4 + j] ^= tmp[k];
        for (int j = 0; j < 4; ++j)
            tmp[j] = gmul(tmp[j], 2);
        for (int j = 0; j < 4; ++j)
            for (int k = 0; k < 2; ++k)
                word[i * 4 + j] ^= tmp[(j + k) % 4];
    }
}

void AES_128::invMixColumns(vector<uint8_t> &word)
{
    vector<uint8_t> tmp(4);
    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
            tmp[j] = word[i * 4 + j];
        word[i * 4 + 0] = gmul(tmp[0], 14) ^ gmul(tmp[1], 11) ^ gmul(tmp[2], 13) ^ gmul(tmp[3], 9);
        word[i * 4 + 1] = gmul(tmp[0], 9) ^ gmul(tmp[1], 14) ^ gmul(tmp[2], 11) ^ gmul(tmp[3], 13);
        word[i * 4 + 2] = gmul(tmp[0], 13) ^ gmul(tmp[1], 9) ^ gmul(tmp[2], 14) ^ gmul(tmp[3], 11);
        word[i * 4 + 3] = gmul(tmp[0], 11) ^ gmul(tmp[1], 13) ^ gmul(tmp[2], 9) ^ gmul(tmp[3], 14);
    }
}

vector<uint8_t> AES_128::encrypt(const vector<uint8_t> &plainText, const vector<uint8_t> &key)
{
    vector<uint8_t> cipherText(plainText);
    vector<uint8_t> expandedKey = keyExpansion(key);
    addRoundKey(expandedKey, 0, cipherText);
    for (int i = 1; i <= 10; ++i)
    {
        subBytes(cipherText);
        shiftRows(cipherText);
        if (i != 10)
            mixColumns(cipherText);
        addRoundKey(expandedKey, i, cipherText);
    }
    return cipherText;
}

vector<uint8_t> AES_128::decrypt(const vector<uint8_t> &cipherText, const vector<uint8_t> &key)
{
    vector<uint8_t> plainText(cipherText);
    vector<uint8_t> expandedKey = keyExpansion(key);
    addRoundKey(expandedKey, 10, plainText);
    for (int i = 9; i >= 0; --i)
    {
        invShiftRows(plainText);
        invSubBytes(plainText);
        addRoundKey(expandedKey, i, plainText);
        if (i != 0)
            invMixColumns(plainText);
    }
    return plainText;
}