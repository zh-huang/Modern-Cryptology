#pragma once
#include <string>
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pXFactoring.h>
using namespace std;

NTL_CLIENT

string toString(ZZ z);

class RSA
{
private:
    /* stores private and public key */
    ZZ a, b, n;
    /* default = 512 bit */
    int size;

public:
    RSA(){};
    RSA(string name);
    void keyGenreate(int keysize = 512);
    void getKey(string &B, string &N);           // get public key
    void getKey(ZZ &B, ZZ &N) { B = b, N = n; }; // get public key
    string encrypt(string plaintext, string B, string N);
    string decrypt(string ciphertext);
    string sign(string message);
    bool verify(string message, string signature, string B, string N);
    void store(string filename);
};