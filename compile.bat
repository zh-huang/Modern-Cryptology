c++ -std=c++17 main.cpp aes128.cpp aescbc.cpp sha1.cpp common.cpp RSA.cpp Certificate.cpp file.cpp NTLlib.a -I D:\Tools\WinNTL-11_5_1\WinNTL-11_5_1\include -Wall -o main.exe
main<test
fc 01_0 01_2 /c /w
echo n | comp 02_0 02_3
fc 04_0 04_3 /w
echo n | comp 06_4 06_0
