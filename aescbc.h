#pragma once

#include <fstream>
#include <vector>
#include <random>
#include <string>

#include "aes128.h"

using namespace std;

class AES_CBC : public AES_128
{
private:
    vector<uint8_t> IV = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

public:
    void encryptFile(const string &inputFilename, const string &outputFilename, const vector<uint8_t> &key);
    void decryptFile(const string &inputFilename, const string &outputFilename, const vector<uint8_t> &key);
    string encryptString(const string &plaintext, const vector<uint8_t> &key);
    string decryptString(const string &ciphertext, const vector<uint8_t> &key);
};
