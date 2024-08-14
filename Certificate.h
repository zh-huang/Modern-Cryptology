#pragma once
#include "RSA.h"
#include <fstream>
#include <algorithm>
#include <sstream>

class Certificate
{
private:
    ZZ a, b, n, size;
    string TA;

public:
    Certificate(string ta = "1002153689");
    void issue(const string &id, const string &ib, const string &in, stringstream &o);
    bool verify(stringstream &i, string &id, string &vb, string &vn);
};
