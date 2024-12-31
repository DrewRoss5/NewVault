#ifndef VaULT_H
#define VAULT_H

#include <fstream>
#include <string>
#include <vector>
#include <stack>

std::string to_hex(const std::vector<unsigned char>& bytes);
void store_hex(const std::string& hex_str, std::vector<unsigned char>& bytes);

struct Key{
    std::vector<unsigned char> salt;
    std::vector<unsigned char> key;
};

class Vault{
    public:
        Vault() {}
        void seal(const std::string& target, const std::string& out_path, const std::string& password);
        void unseal(const std::string& target, const std::string& out_path, const std::string& password);
        void clear();
    private:
        void encrypt_file(const std::string& file_path, std::ofstream& out_file);
        void parse_chunk(std::ifstream& vault_f, std::vector<unsigned char>& buf); 
        void parse_salt(std::ifstream& vault_f, std::vector<unsigned char>& salt_buf);
        void parse_header(std::ifstream& vault_f, Key& key, std::string& file_name);
        std::stack<Key> key_stack;
        std::stack<std::string> path_stack;
};

#endif