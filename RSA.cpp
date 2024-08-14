#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include "RSA.h"

string toString(ZZ z)
{
    std::ostringstream oss;
    oss << z;
    return oss.str();
}

NTL::ZZ ZZFromStr(const std::string &str)
{
    NTL::ZZ number;
    std::stringstream ss(str);
    ss >> number;
    return number;
}

RSA::RSA(string name)
{
    ifstream i = ifstream(name.c_str(), ios::in);
    if (!i.is_open())
    {
        cerr << "RSA.cpp RSA::RSA(): input error" << endl;
        return;
    }
    i >> a >> b >> n >> size;
    i.close();
}

void RSA::keyGenreate(int key_size)
{
    if (key_size != 512 && key_size != 1024)
    {
        cerr << "RSA.cpp RSA::keyGenerate: key_size should be 512 or 1024" << endl;
        return;
    }
    ZZ p, q, phi;
    size = key_size;
    GenGermainPrime(p, size);
    GenGermainPrime(q, size);
    while (p == q)
        GenGermainPrime(q, size);
    n = p * q;
    phi = (p - 1) * (q - 1);
    do
    {
        RandomBnd(b, phi);
    } while (GCD(b, phi) != 1);
    InvMod(a, b, phi);
}

void RSA::getKey(string &B, string &N)
{
    B = toString(b);
    N = toString(n);
}

string RSA::encrypt(string plaintext, string B, string N)
{
    ZZ pt = conv<ZZ>(plaintext.c_str());
    ZZ eb = conv<ZZ>(B.c_str());
    ZZ en = conv<ZZ>(N.c_str());
    ZZ ciphertext;
    PowerMod(ciphertext, pt, eb, en);
    return toString(ciphertext);
}

string RSA::decrypt(string ciphertext)
{
    ZZ ct = conv<ZZ>(ciphertext.c_str());
    ZZ plaintext;
    PowerMod(plaintext, ct, a, n);
    return toString(plaintext);
}

string RSA::sign(string message)
{
    ZZ m, s, mm;
    m = ZZFromStr(message);
    rem(mm, m, n);
    s = PowerMod(m, a, n);
    string signature = toString(s);
    return signature;
}

bool RSA::verify(string message, string signature, string B, string N)
{
    ZZ m, s;
    m = ZZFromStr(message);
    s = ZZFromStr(signature);
    ZZ e = ZZFromStr(B);
    ZZ mod = ZZFromStr(N);
    ZZ computedSignature = PowerMod(s, e, mod);
    return m == computedSignature;
}

void RSA::store(string filename)
{
    ofstream o(filename, ios::out | ios::binary);
    o << a << endl;
    o << b << endl;
    o << n << endl;
    o << size << endl;
    o.close();
}