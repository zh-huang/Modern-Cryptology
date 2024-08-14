#include "Certificate.h"
#include "sha1.h"
using namespace std;

Certificate::Certificate(string ta)
{
    ifstream in("cert.cert", ios::in | ios::binary);
    if (!in.is_open())
    {
        RSA rsa;
        rsa.keyGenreate(1024);
        rsa.store("cert.cert");
        std::ofstream outputFile("cert.cert", ios::out | ios_base::app);
        TA = ta;
        outputFile << TA << endl;
        outputFile.close();
        in = ifstream("cert.cert", ios::in | ios::binary);
    }
    in >> a >> b >> n >> size >> TA;
    in.close();
}

void Certificate::issue(const string &id, const string &ib, const string &in, stringstream &o)
{
    string plain = ib + in + id;
    SHA_1 sha;
    ZZ plainh = sha.sha1zz(plain);
    ZZ cert = PowerMod(plainh, a, n);
    o << id << endl;
    o << ib << endl;
    o << in << endl;
    o << ib.length() << endl;
    o << in.length() << endl;
    o << cert << endl;
    o << TA << endl;
}

bool Certificate::verify(stringstream &i, string &id, string &vb, string &vn)
{
    int flagb, flagn;
    string ta;
    ZZ cert, cb, cn;
    i >> id >> vb >> vn >> flagb >> flagn >> cert >> ta;
    if (ta != "1002153689")
        return false;
    if ((int)vb.length() != flagb || (int)vn.length() != flagn)
        return false;
    string plain = vb + vn + id;
    SHA_1 sha;
    ZZ plainh = sha.sha1zz(plain);
    ZZ certd = PowerMod(cert, b, n);
    return (bool)(certd == plainh);
}