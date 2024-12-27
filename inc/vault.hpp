#ifndef VaULT_H
#define VAULT_H

#include <string>
#include <vector>
#include <stdexcept>



// enrypts a file or a directory. If the path is a directory, this recursively encrypts it's children. Returns the ciphertext as a vector
std::vector<unsigned char> encrypt_file(std::string path);
std::vector<unsigned char> decrypt_file(std::string path);


#endif