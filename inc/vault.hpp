#ifndef VaULT_H
#define VAULT_H

#include <string>
#include <vector>
#include <stdexcept>

std::vector<unsigned char> encrypt_file(std::string path);
std::vector<unsigned char> decrypt_file(std::string path);

#endif