#ifndef CRYPTOUTILS_H
#define CRYPTOUTILS_H

#include <string>
#include <vector> 

void gen_salt(std::vector<unsigned char>& salt);
std::vector<unsigned char> gen_key(const std::string& password, const std::vector<unsigned char>& salt);
std::vector<unsigned char> hash_key(const std::vector<unsigned char>& key, const std::vector<unsigned char>& salt);
std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key, std::vector<unsigned char>& ciphertext);
std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, std::vector<unsigned char>& plaintext);

#endif