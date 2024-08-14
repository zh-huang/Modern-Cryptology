#include "aescbc.h"

string AES_CBC::encryptString(const string &plaintext, const vector<uint8_t> &key)
{
    string ciphertext;
    vector<uint8_t> block(16);
    vector<uint8_t> lastCipherBlock = IV;
    for (int blocki = 0; blocki < (int)plaintext.size() / 16; ++blocki)
    {
        for (int i = 0; i < 16; ++i)
            block[i] = lastCipherBlock[i] ^ plaintext[i + blocki * 16];
        lastCipherBlock = encrypt(block, key);
        ciphertext.append(reinterpret_cast<const char *>(&lastCipherBlock[0]), 16);
    }
    int k = plaintext.size() % 16;
    for (int i = 0; i < 16; ++i)
        block[i] = lastCipherBlock[i] ^ (i < k ? plaintext[plaintext.size() - k + i] : 16 - k);
    lastCipherBlock = encrypt(block, key);
    ciphertext.append(reinterpret_cast<const char *>(&lastCipherBlock[0]), 16);
    return ciphertext;
}

string AES_CBC::decryptString(const string &ciphertext, const vector<uint8_t> &key)
{
    string plaintext;
    vector<uint8_t> block(16);
    vector<uint8_t> lastCipherBlock = IV;
    for (int blocki = 0; blocki < (int)(ciphertext.size() + 15) / 16; ++blocki)
    {
        for (int i = 0; i < 16; ++i)
            block[i] = ciphertext[i + blocki * 16];
        vector<uint8_t> plainBlock = decrypt(block, key);
        for (int i = 0; i < 16; ++i)
            plainBlock[i] ^= lastCipherBlock[i];
        if (blocki < (int)(ciphertext.size() - 1) / 16)
            plaintext.append(reinterpret_cast<const char *>(&plainBlock[0]), 16);
        else if (plainBlock[15] < 16)
            plaintext.append(reinterpret_cast<const char *>(&plainBlock[0]), 16 - plainBlock[15]);
        lastCipherBlock = block;
    }
    return plaintext;
}

void AES_CBC::encryptFile(const string &inputFilename, const string &outputFilename, const vector<uint8_t> &key)
{
    ifstream inputFile(inputFilename, ios::binary);
    if (!inputFile.is_open())
    {
        cerr << "aescbc.cpp AESCBC::encryptfile: infile error" << endl;
        return;
    }
    istreambuf_iterator<char> beg(inputFile), end;
    string message(beg, end);
    inputFile.close();
    string cipher = encryptString(message, key);
    ofstream outputFile(outputFilename, ios::binary);
    outputFile.write(cipher.c_str(), cipher.size());
    outputFile.close();
}

void AES_CBC::decryptFile(const string &inputFilename, const string &outputFilename, const vector<uint8_t> &key)
{
    ifstream inputFile(inputFilename, ios::binary);
    if (!inputFile.is_open())
    {
        cerr << "aescbc.cpp AESCBC::decryptfile: infile error" << endl;
        return;
    }
    istreambuf_iterator<char> beg(inputFile), end;
    string message(beg, end);
    inputFile.close();
    string plain = decryptString(message, key);
    ofstream outputFile(outputFilename, ios::binary);
    outputFile.write(plain.c_str(), plain.size());
    outputFile.close();
}
