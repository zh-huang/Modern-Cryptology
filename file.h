#pragma once
#include "aescbc.h"
#include "Certificate.h"
#include "RSA.h"
#include "sha1.h"

NTL_CLIENT

using namespace std;

class fileEncrypt : Certificate
{
public:
    void send(RSA &sender, const string &inFileName, const string &outFileName, const string &sSign, const string &rSign);
    void receive(RSA &receiver, const string &inFileName, const string &outFileName, const string &sSign, const string &rSign);
};