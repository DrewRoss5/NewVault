#ifndef VaULT_H
#define VAULT_H

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
        void seal(const std::string& target, const std::string& out_path, const std::string& password);
        void unseal(const std::string& target, const std::string& out_path, const std::string& password);
    private:
        void encrypt_file(const std::string& file_path, std::ofstream& out_file);
        void parse_chunk(std::ifstream& vault_f, std::vector<unsigned char>& buf); 
        void parse_salt(std::ifstream& vault_f, std::vector<unsigned char>& salt_buf);
        std::stack<Key> key_stack;
        std::stack<std::string> path_stack;
};

#endif