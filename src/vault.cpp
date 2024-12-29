#include <stack>
#include <vector>
#include <fstream>
#include <stdexcept>
#include <filesystem>
#include <iostream>

#include "../inc/vault.hpp"
#include "../inc/cryptoutils.hpp"

#ifdef _WIN32
    #define PATH_SEP '\\'
#else 
    #define PATH_SEP '/'
#endif

#define CRYPTO_OFFSET 40 // the size of the MAC and nonce in ciphertext (16 + 24)'
#define SALT_SIZE 16
#define BEGIN_DIR 'd'
#define END_DIR 'D'
#define BEGIN_FILE 'f'
#define SEP_CHAR ';'


namespace fs = std::filesystem;

// converts an unsigned char vector to a hex string
std::string to_hex(const std::vector<unsigned char>& bytes){
    std::stringstream ss;
    for (int i = 0; i < bytes.size(); i++)
        ss << std::setw(2) <<std::hex <<std::setfill('0') << (int)  bytes[i];
    return ss.str();
}

// decodes a hex string and creates a vector of unsigned characters from it 
std::vector<unsigned char> from_hex(const std::string& hex_str){
    std::istringstream hex_stream(hex_str);
    std::vector<unsigned char> bytes;
    unsigned int tmp;
    while (hex_stream >> std::hex >> tmp)
        bytes.push_back(tmp);
    return bytes;
}

// encrypts a the given path and stores it to the target file 
void Vault::seal(const std::string& target, const std::string& out_file,  const std::string& password){
    // ensure the path exists
    if (!fs::exists(target))
        throw std::runtime_error("cannot encrypt " + target + ", does it exist?");
    // generate a key from the given password
    Key master_key;
    gen_salt(master_key.salt);
    master_key.key = gen_key(password, master_key.salt);
    this->key_stack.push(master_key);
    // create the encrypted file
    std::ofstream out(out_file, std::ios::binary);
    out << to_hex(master_key.salt);
    this->encrypt_file(target, out);
    out.close();

}

// decrypts a vault archive file and stores the contents to the output directory
void Vault::unseal(const std::string& target, const std::string& out_path, const std::string& password){
    
}

// encrypts the given file/directory. If it's a directory, this recursively encrypts the children. Writes the ciphertext to the file stream
void Vault::encrypt_file(const std::string& file_path, std::ofstream& out_f){
    std::string file_name = fs::path(file_path).filename();
    // genereate a key for the file
    Key prev_key {this->key_stack.top()}, file_key;
    gen_salt(file_key.salt);
    file_key.key = hash_key(prev_key.key, file_key.salt);
    if (fs::is_directory(file_path)){
        this->key_stack.push(file_key);
        // encrypt the directory's name
        std::vector<unsigned char> dir_name(file_name.begin(), file_name.end());
        std::vector<unsigned char> dir_name_cipher;
        encrypt(dir_name, file_key.key, dir_name_cipher);
        // write the directory header to the vault file
        out_f << BEGIN_DIR << to_hex(file_key.salt) << to_hex(dir_name_cipher) << SEP_CHAR;
        // write the contents of the directory to the file
        for (const auto &entry : fs::directory_iterator(file_path))
            this->encrypt_file(entry.path(), out_f);
        // end the diretory 
        out_f << END_DIR;
        this->key_stack.pop();
    }
    else{
        // encrypt the file's name
        std::vector<unsigned char> file_name_bytes(file_name.begin(), file_name.end());
        std::vector<unsigned char> file_name_cipher;
        encrypt(file_name_bytes, file_key.key, file_name_cipher);
        // encrypt the file's contents 
        std::ifstream plaintext_f(file_path);
        std::vector<unsigned char> contents_plain, contents_cipher;
        char tmp;
        while (plaintext_f.get(tmp))
            contents_plain.push_back(tmp);
        encrypt(contents_plain, file_key.key, contents_cipher);
        // write the encrypted file to the vault 
        out_f << BEGIN_FILE << to_hex(file_key.salt) << to_hex(file_name_cipher) << SEP_CHAR << to_hex(contents_cipher) << SEP_CHAR;
    } 
}

// decrypts the given file from a partially read vault file
void Vault::decrypt_file(std::ifstream& vault_f){

}