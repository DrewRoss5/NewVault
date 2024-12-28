#ifndef VaULT_H
#define VAULT_H

#define BEGIN_DIR (unsigned char) 0x10
#define END_DIR (unsigned char) 0x11
#define BEGIN_FILE (unsigned char) 0x12
#define NULL_TERM (unsigned char) 0x0

#include <fstream>
#include <string>
#include <vector>
#include <stack>

struct Key{
    std::vector<unsigned char> salt;
    std::vector<unsigned char> key;
};

class Vault{
    public:
        Vault() {}
        void seal(const std::string& target, const std::string& password, const std::string& out_path);
        void unseal(const std::string& file_path, std::string& password);
    private:
        void encrypt_file(const std::string& file_path, std::ofstream& out_file);
        std::stack<Key> key_stack;
        std::stack<std::string> path_stack;
};

#endif