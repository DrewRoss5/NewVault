#include <stack>
#include <vector>
#include <fstream>
#include <stdexcept>
#include <filesystem>
#include <sstream>
#include <iostream>

#include "../inc/vault.hpp"
#include "../inc/cryptoutils.hpp"

#ifdef _WIN32
    #define PATH_SEP '\\'
#else 
    #define PATH_SEP '/'
#endif

#define CRYPTO_OFFSET 40 // the size of the MAC and nonce in ciphertext (16 + 24)'
#define SALT_SIZE_HEX 32
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
void store_hex(const std::string& hex_str, std::vector<unsigned char>& bytes){
    for (size_t i = 0; i < hex_str.length(); i += 2) {
        std::string byte_string = hex_str.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byte_string, nullptr, 16));
        bytes.push_back(byte);
    }
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
    // ensure the output path is a valid direct
    if (!fs::is_directory(out_path)){
        if (!fs::exists(out_path))
            fs::create_directory(out_path);
        else
            throw std::runtime_error("invalid output path");
    }
    // open the vault file 
    std::ifstream vault_f(target);
    if (!vault_f.good())
        throw std::runtime_error("failed to read the vault file. Does it exist?");
    // read the salt from the vault file
    Key master_key;
    std::vector<unsigned char> master_key_salt;
    parse_salt(vault_f, master_key_salt);
    master_key.salt = master_key_salt;
    master_key.key = gen_key(password, master_key.salt);
    key_stack.push(master_key);
    path_stack.push(out_path);
    // read the contents of the vault 
    // we assume that any character reached in this part of the loop is a vault/file header 
    char header_char;
    Key file_key, prev_key;
    std::vector<unsigned char> name_ciphertext, name_plaintext, file_ciphertext, file_plaintext;
    std::string file_name, file_path;
    std::ofstream out_f;
    while (vault_f.get(header_char)){
        switch (header_char){
            case BEGIN_DIR:
                prev_key = this->key_stack.top();
                // parse the vault header
                parse_salt(vault_f, file_key.salt);
                file_key.key = hash_key(prev_key.key, file_key.salt);
                parse_chunk(vault_f, name_ciphertext);
                decrypt(name_ciphertext, file_key.key, name_plaintext);
                file_name = std::string(name_plaintext.begin(), name_plaintext.end());
                file_path = this->path_stack.top() + PATH_SEP + file_name;
                fs::create_directory(file_path);
                // update the stacks
                key_stack.push(file_key);
                path_stack.push(file_path);
                break;
            case BEGIN_FILE:
                prev_key = this->key_stack.top();
                // parse the file header 
                parse_salt(vault_f, file_key.salt);
                file_key.key = hash_key(prev_key.key, file_key.salt);
                parse_chunk(vault_f, name_ciphertext);
                decrypt(name_ciphertext, file_key.key, name_plaintext);
                file_name = std::string(name_plaintext.begin(), name_plaintext.end());
                file_path = this->path_stack.top() + PATH_SEP + file_name;
                // decrypt the file's contents and write it
                parse_chunk(vault_f, file_ciphertext);
                decrypt(file_ciphertext, file_key.key, file_plaintext);
                out_f = std::ofstream(file_path, std::ios::binary);
                out_f.write(reinterpret_cast<char*>(&file_plaintext[0]), file_plaintext.size());
                break;
            case END_DIR:
                /* 
                    end_dir should only be encountered if a directory's key is on the stack, and the vault's
                    master key should always be on the stack below any directory keys, so if there are fewer
                    than two keys on the key stack, we've reached the end of a directory that never started,
                    making the vault file invalid
                */
                if (this->key_stack.size() < 2)
                    throw std::runtime_error("invalid vault file");
                this->key_stack.pop();
                this->path_stack.pop();
                break;
            default:
                throw std::runtime_error("invalid vault file");
                break;
        }
    }
    

}

// encrypts the given file/directory. If it's a directory, this recursively encrypts the children. 
// Writes the ciphertext to the file stream
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

// parses a chunk of a vault file to the next seperating character and returns the resulting bytes
void Vault::parse_chunk(std::ifstream& vault_f, std::vector<unsigned char>& buf){
    buf.clear();
    std::string hex_str;
    char c;
    while (vault_f.get(c) && c != SEP_CHAR)
        hex_str += c;
    buf.clear();
    store_hex(hex_str, buf);
}

// parses a 16-byte salt from the vault file 
void Vault::parse_salt(std::ifstream& vault_f, std::vector<unsigned char>& salt_buf){
    salt_buf.clear();
    char salt_hex[SALT_SIZE_HEX + 1];
    vault_f.read(salt_hex, SALT_SIZE_HEX);
    salt_hex[SALT_SIZE_HEX] = '\0';
    store_hex(salt_hex, salt_buf);
}