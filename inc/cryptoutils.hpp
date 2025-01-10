#ifndef CRYPTOUTILS_H
#define CRYPTOUTILS_H

#include <string>
#include <vector> 

void rand_bytes(std::vector<unsigned char>& buf, unsigned  size);
std::vector<unsigned char> gen_key(const std::string& password, const std::vector<unsigned char>& salt);
std::vector<unsigned char> hash_key(const std::vector<unsigned char>& key, const std::vector<unsigned char>& salt);
void encrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key, std::vector<unsigned char>& ciphertext);
void decrypt(std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, std::vector<unsigned char>& plaintext);

#endif