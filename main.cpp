// 2153689 HZH
#include "aes128.h"
#include "aescbc.h"
#include "sha1.h"
#include "common.h"
#include "RSA.h"
#include "Certificate.h"
#include "file.h"
#include <cstdlib>
#include <Windows.h>

using namespace std;

void aesEncrypt()
{
    cout << "main.cpp aesEncrypt: AES encryption starts" << endl;
    string infile, outfile;
    cin >> infile >> outfile;
    ifstream i(infile.c_str(), ios::binary | ios::in);
    if (!i.is_open())
    {
        cerr << "main.cpp aesEncrypt: infile error" << endl;
        return;
    }
    cout << "main.cpp aesEncrypt: reading " << infile << endl;
    vector<uint8_t> key;
    vector<uint8_t> plainText(16, 0);
    cout << "main.cpp aesEncrypt: reading key" << endl;
    for (auto &k : plainText)
        if (!readHex(i, k))
        {
            cerr << "main.cpp aesEncrypt: not 128 bit" << endl;
            return;
        }
    if (key.size() != 16)
    {
        cerr << "main.cpp aesEncrypt: regenerating key" << endl;
        key.resize(16);
        for (auto &i : key)
            i = rand() % 256;
    }
    cout << "main.cpp aesEncrypt: encrypting" << endl;
    AES_128 aes;
    vector<uint8_t> cipherText = aes.encrypt(plainText, key);
    ofstream o(outfile.c_str(), ios::binary | ios::out);
    o << printHex(cipherText).str() << endl;
    o << printHex(key).str() << endl;
    i.close();
    o.close();
    cout << "main.cpp aesEncrypt: success!" << endl;
    cout << endl;
}

void aesDecrypt()
{
    cout << "main.cpp aesDecrypt: AES decryption starts" << endl;
    string infile, outfile;
    cin >> infile >> outfile;
    cout << "main.cpp aesDecrypt: reading " << infile << endl;
    ifstream i(infile.c_str(), ios::binary | ios::in);
    if (!i.is_open())
    {
        cerr << "main.cpp aesDecrypt: infile error" << endl;
        return;
    }
    vector<uint8_t> cipherText(16, 0);
    vector<uint8_t> key(16);
    cout << "main.cpp aesDecrypt: reading key" << endl;
    for (auto &k : cipherText)
        if (!readHex(i, k))
        {
            cerr << "main.cpp aesDecrypt: not 128 bit" << endl;
            return;
        }
    for (auto &k : key)
        if (!readHex(i, k))
        {
            cerr << "main.cpp aesDecrypt: key inavailable" << endl;
            return;
        }
    cout << "main.cpp aesDecrypt: decrypting" << endl;
    AES_128 aes;
    vector<uint8_t> plainText = aes.decrypt(cipherText, key);
    ofstream o(outfile.c_str(), ios::binary | ios::out);
    o << printHex(plainText).str() << endl;
    i.close();
    o.close();
    cout << "main.cpp aesDecrypt: success!" << endl;
    cout << endl;
}

void CBCencrypt()
{
    cout << "main.cpp CBCencrypt: CBC encryption starts" << endl;
    string infile, outfile, keyfile;
    cin >> infile >> outfile >> keyfile;
    cout << "main.cpp CBCdecrypt: generating key" << endl;
    vector<uint8_t> key(16);
    for (auto &i : key)
        i = rand() % 256;
    AES_CBC aes;
    cout << "main.cpp CBCencrypt: encrypting" << endl;
    aes.encryptFile(infile, outfile, key);
    cout << "main.cpp CBCencrypt: saving key" << endl;
    ofstream keyout(keyfile, ios::binary | ios::out);
    keyout << printHex(key).str() << endl;
    keyout.close();
    cout << "main.cpp CBCencrypt: success!" << endl;
    cout << endl;
}

void CBCdecrypt()
{
    cout << "main.cpp CBCdecrypt: CBC decryption starts" << endl;
    string infile, outfile, keyfile;
    cin >> infile >> outfile >> keyfile;
    vector<uint8_t> key(16);
    ifstream input(keyfile, ios::binary | ios::in);
    if (!input.is_open())
    {
        cerr << "main.cpp CBCdecrypt: infile error" << endl;
        return;
    }
    for (auto &k : key)
        if (!readHex(input, k))
        {
            cerr << "main.cpp CBCdecrypt: key inavailable" << endl;
            exit(-1);
        }
    input.close();
    cout << "main.cpp CBCdecrypt: decrypting" << endl;
    AES_CBC aes;
    aes.decryptFile(infile, outfile, key);
    cout << "main.cpp CBCdecrypt: success!" << endl;
    cout << endl;
}

void SHA1()
{
    string infile;
    cin >> infile;
    cout << "main.cpp SHA1: reading infile" << endl;
    ifstream inputFile(infile, ios::binary | ios::in);
    if (!inputFile.is_open())
    {
        cerr << "main.cpp SHA1: infile error" << endl;
        return;
    }
    istreambuf_iterator<char> beg(inputFile), end;
    string message(beg, end);
    inputFile.close();
    SHA_1 sha;
    cout << sha.sha1(message) << endl;
    cout << endl;
}

void RSAencrypt()
{
    cout << "main.cpp RSAencrypt: RSA encryption starts" << endl;
    string infile, outfile, keyfile, message, b, n;
    int keysize;
    cin >> infile >> outfile >> keyfile >> keysize;
    if (keysize != 512 && keysize != 1024)
    {
        cerr << "main.cpp RSAencrypt: keysize should be 512 or 1024" << endl;
        return;
    }
    cout << "main.cpp RSAencrypt: reading " << infile << endl;
    ifstream inputFile(infile, ios::binary | ios::in);
    if (!inputFile.is_open())
    {
        cerr << "main.cpp RSAencrypt: infile error" << endl;
        return;
    }
    inputFile >> message;
    inputFile.close();
    RSA rsa;
    cout << "main.cpp RSAencrypt: encrypting" << endl;
    rsa.keyGenreate(keysize);
    rsa.getKey(b, n);
    string ciphertext = rsa.encrypt(message, b, n);
    ofstream output(outfile, ios::binary | ios::out);
    output << ciphertext << endl;
    output.close();
    rsa.store(keyfile);
    cout << "main.cpp RSAencrypt: success" << endl;
    cout << endl;
}

void RSAdecrypt()
{
    cout << "main.cpp RSAdecrypt: RSA decryption starts" << endl;
    string infile, outfile, keyfile, message, b, n;
    cin >> infile >> outfile >> keyfile;
    cout << "main.cpp RSAdecrypt: reading " << infile << endl;
    ifstream inputFile(infile, ios::binary | ios::in);
    if (!inputFile.is_open())
    {
        cerr << "main.cpp RSAdecrypt: infile error" << endl;
        return;
    }
    inputFile >> message;
    inputFile.close();
    cout << "main.cpp RSAdecrypt: reading " << keyfile << endl;
    RSA rsa(keyfile);
    ofstream output(outfile, ios::binary | ios::out);
    cout << "main.cpp RSAdecrypt: decrypting" << endl;
    output << rsa.decrypt(message) << endl;
    output.close();
    cout << "success" << endl;
    cout << endl;
}

void RSAsign()
{
    cout << "main.cpp RSAsign: RSA signing starts" << endl;
    string infile, outfile, keyfile, message, b, n;
    int keysize;
    cin >> infile >> outfile >> keyfile >> keysize;
    if (keysize != 512 && keysize != 1024)
    {
        cerr << "main.cpp RSAsign: keysize should be 512 or 1024" << endl;
        return;
    }
    cout << "main.cpp RSAsign: reading " << infile << endl;
    ifstream inputFile(infile, ios::binary | ios::in);
    if (!inputFile.is_open())
    {
        cerr << "main.cpp RSAsign: infile error" << endl;
        return;
    }
    inputFile >> message;
    inputFile.close();
    RSA rsa;
    cout << "main.cpp RSAsign: signing" << endl;
    rsa.keyGenreate(keysize);
    rsa.getKey(b, n);
    string ciphertext = rsa.sign(message);
    ofstream output(outfile, ios::binary | ios::out);
    output << ciphertext << endl;
    output.close();
    ofstream keyout(keyfile, ios::binary | ios::out);
    keyout << b << endl;
    keyout << n << endl;
    keyout.close();
    cout << "main.cpp RSAsign: success" << endl;
    cout << endl;
}

void RSAverify()
{
    cout << "main.cpp RSAverify: RSA verifying starts" << endl;
    string infile, outfile, keyfile, message, b, n, sign;
    cin >> infile >> outfile >> keyfile;
    cout << "main.cpp RSAverify: reading" << infile << endl;
    ifstream inputFile(infile, ios::binary | ios::in);
    if (!inputFile.is_open())
    {
        cerr << "main.cpp RSAverify: infile error" << endl;
        return;
    }
    inputFile >> message;
    inputFile.close();
    cout << "main.cpp RSAverify: reading " << keyfile << endl;
    ifstream keyFile(keyfile, ios::binary | ios::in);
    if (!keyFile.is_open())
    {
        cerr << "main.cpp RSAverify: keyfile error" << endl;
        return;
    }
    keyFile >> b >> n;
    keyFile.close();
    cout << "main.cpp RSAverify: reading " << outfile << endl;
    ifstream signFile(outfile, ios::binary | ios::in);
    if (!signFile.is_open())
    {
        cerr << "main.cpp RSAverify: signfile error" << endl;
        return;
    }
    signFile >> sign;
    signFile.close();
    RSA rsa;
    if (rsa.verify(message, sign, b, n))
        cout << "Verified" << endl;
    else
        cout << "Not verified" << endl;
    cout << endl;
}

void generatesign()
{
    cout << "main.cpp generatesign: generating sign" << endl;
    string id, pubkeyfilename, prikeyfilename, signfilename, b, n;
    int keysize;
    cin >> id >> pubkeyfilename >> prikeyfilename >> signfilename >> keysize;
    RSA rsa;
    rsa.keyGenreate(keysize);
    rsa.store(prikeyfilename);
    rsa.getKey(b, n);
    ofstream pubkeyfile(pubkeyfilename, ios::binary | ios::out);
    pubkeyfile << b << endl;
    pubkeyfile << n << endl;
    pubkeyfile.close();
    stringstream ss;
    Certificate cert;
    cert.issue(id, b, n, ss);
    ofstream signfile(signfilename, ios::binary | ios::out);
    signfile << ss.str();
    signfile.close();
    cout << "main.cpp generatesign: success" << endl;
    cout << endl;
}

void sendfile()
{
    cout << "main.cpp sendfile: Sending file" << endl;
    string infile, outfile, prikeyfile, sendersign, receriversign, senderid, senderb, sendern;
    cin >> infile >> outfile >> prikeyfile >> sendersign >> receriversign;
    RSA sender(prikeyfile);
    ifstream sendersignfile(sendersign, ios::binary | ios::in);
    if (!sendersignfile.is_open())
    {
        cerr << "main.cpp sendfile: sendersign error" << endl;
        return;
    }
    istreambuf_iterator<char> beg1(sendersignfile), end1;
    string sendersignmessage(beg1, end1);
    sendersignfile.close();

    ifstream receriversignfile(receriversign, ios::binary | ios::in);
    if (!receriversignfile.is_open())
    {
        cerr << "main.cpp sendfile: receriversign error" << endl;
        return;
    }
    istreambuf_iterator<char> beg2(receriversignfile), end2;
    string receiversignmessage(beg2, end2);
    receriversignfile.close();

    fileEncrypt file;
    file.send(sender, infile, outfile, sendersignmessage, receiversignmessage);
    cout << "main.cpp sendfile: file sended to " << outfile << " successfully" << endl;
    cout << endl;
}

void receivefile()
{
    cout << "main.cpp receivefile: receiving file" << endl;
    string infile, outfile, prikeyfile, sendersign, receriversign, senderid, senderb, sendern;
    cin >> infile >> outfile >> prikeyfile >> sendersign >> receriversign;
    RSA receiver(prikeyfile);

    ifstream sendersignfile(sendersign, ios::binary | ios::in);
    if (!sendersignfile.is_open())
    {
        cerr << "main.cpp sendfile: sendersign error" << endl;
        return;
    }
    istreambuf_iterator<char> beg1(sendersignfile), end1;
    string sendersignmessage(beg1, end1);
    sendersignfile.close();

    ifstream receriversignfile(receriversign, ios::binary | ios::in);
    if (!receriversignfile.is_open())
    {
        cerr << "main.cpp sendfile: receriversign error" << endl;
        return;
    }
    istreambuf_iterator<char> beg2(receriversignfile), end2;
    string receiversignmessage(beg2, end2);
    receriversignfile.close();

    fileEncrypt file;
    file.receive(receiver, infile, outfile, sendersignmessage, receiversignmessage);
    cout << "main.cpp receivefile: file received to " << outfile << " successfully!" << endl;
    cout << endl;
}

void usage()
{
    cout << "AESencrypt   [infilename] [outfilename]: AES encrypt 128 bit" << endl;
    cout << "AESdecrypt   [infilename] [outfilename]: AES decrypt 128 bit" << endl;
    cout << "CBCencrypt   [infilename] [outfilename] [keyfilename]: AES encrypt CBC mode" << endl;
    cout << "CBCdecrypt   [infilename] [outfilename] [keyfilename]: AES decrypt CBC mode" << endl;
    cout << "SHA1         [infilename]: SHA-1" << endl;
    cout << "RSAencrypt   [infilename] [outfilename] [keyfile] [keysize]: RSA encrypt" << endl;
    cout << "RSAdecrypt   [infilename] [outfilename] [keyfile]: RSA decrypt" << endl;
    cout << "RSAsign      [messagefile] [signfile] [keyfile] [keysize]: RSA sign" << endl;
    cout << "RSAverify    [messagefile] [signfile] [keyfile]: RSA signature verify" << endl;
    cout << "generatesign [id] [pubkeyfile] [prikeyfile] [signfile] [keysize]: RSA signature verify" << endl;
    cout << "sendfile     [infile] [outfile] [prikeyfile] [sendersign] [receiversign]: RSA signature verify" << endl;
    cout << "receivefile  [infile] [outfile] [prikeyfile] [sendersign] [receiversign]: RSA signature verify" << endl;
    cout << "quit : exit" << endl;
    cout << "help : show help" << endl;
    cout << "E.g.   AESencrypt infile.txt outfile.txt" << endl;
    cout << "       RSAencrypt infile.txt outfile.txt keyfile.key 512" << endl;
    cout << endl;
}

int main(int argv, char **argc)
{
    usage();
    while (1)
    {
        string type;
        cin >> type;
        if (type == "help")
            usage();
        else if (type == "quit")
            break;
        else if (type == "AESencrypt")
            aesEncrypt();
        else if (type == "AESdecrypt")
            aesDecrypt();
        else if (type == "CBCencrypt")
            CBCencrypt();
        else if (type == "CBCdecrypt")
            CBCdecrypt();
        else if (type == "SHA1")
            SHA1();
        else if (type == "RSAencrypt")
            RSAencrypt();
        else if (type == "RSAdecrypt")
            RSAdecrypt();
        else if (type == "RSAsign")
            RSAsign();
        else if (type == "RSAverify")
            RSAverify();
        else if (type == "generatesign")
            generatesign();
        else if (type == "sendfile")
            sendfile();
        else if (type == "receivefile")
            receivefile();
    }
    return 0;
}