#include "file.h"
#include "sha1.h"
#include <cstdlib>
#include <Windows.h>

void fileEncrypt::send(RSA &sender, const string &inFileName, const string &outFilename, const string &sSign, const string &rSign)
{
    // verify receiver's signature
    string c1, c2, rid, rb, rn;
    stringstream srSign(rSign);
    if (!verify(srSign, rid, rb, rn))
    {
        cout << "Send receiver certificate not verified." << endl;
        return;
    }
    cout << "Send receiver certificate verified." << endl;

    // encrypt key to c2
    vector<uint8_t> key(16);
    for (auto &i : key)
        i = rand() % 256;
    ZZ zkey = conv<ZZ>(0);
    for (auto &i : key)
        zkey = (zkey * 256) + (unsigned int)i;
    c2 = sender.encrypt(toString(zkey), rb, rn);

    // read message
    ifstream in(inFileName, ios::in | ios::binary);
    istreambuf_iterator<char> beg(in), end;
    string message(beg, end);
    in.close();

    // encrypt message
    ZZ b, n;
    sender.getKey(b, n);
    stringstream o;
    issue(rid, toString(b), toString(n), o);
    SHA_1 sha;
    o << sSign << endl;
    ZZ hashm = sha.sha1zz(message);
    o << hashm << endl;
    o << message;
    AES_CBC aes;
    srand((unsigned)time(NULL));
    c1 = aes.encryptString(o.str(), key);
    string cMessage = c2 + '\n' + c1;
    ofstream outFile(outFilename.c_str(), ios::out | ios::binary);
    outFile.write(cMessage.c_str(), cMessage.size());
    outFile.close();
}

void fileEncrypt::receive(RSA &receiver, const string &inFileName, const string &outFileName, const string &sSign, const string &rSign)
{
    ifstream inFile(inFileName, ios::in | ios::binary);
    if (!inFile.is_open())
    {
        cout << "file not opened. From fileEncrypt::receive()" << endl;
        return;
    }
    string c1, c2;
    int c;
    while ((c = inFile.get()) != '\n')
        c2 += c;
    while ((c = inFile.get()) != EOF)
        c1 += c;
    inFile.close();
    ZZ zkey = conv<ZZ>(receiver.decrypt(c2).c_str());
    vector<uint8_t> key(16);
    for (int i = 15; i >= 0; --i, zkey /= 256)
        key[i] = (uint8_t)(zkey % 256);
    AES_CBC aes;
    stringstream i(aes.decryptString(c1, key));
    string sid, sb, sn, tmp[8];
    if (verify(i, sid, sb, sn))
        cout << "sender verified" << endl;
    else
        cout << "sender not verified" << endl;
    ZZ hash;

    // get message and save it to file
    i >> tmp[0] >> tmp[1] >> tmp[2] >> tmp[3] >> tmp[4] >> tmp[5] >> tmp[6];
    i >> hash;
    i.get();
    string message = i.str().substr(i.tellg());
    ofstream ofile(outFileName, ios::out | ios::binary);
    ofile.write(message.c_str(), message.length());
    ofile.close();
    SHA_1 sha;
    ZZ hashm = sha.sha1zz(message);
    if (hashm == hash)
        cout << "message verified" << endl;
    else
        cout << "message not verified" << endl;
}