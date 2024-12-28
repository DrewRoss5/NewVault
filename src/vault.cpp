#include <stack>
#include <vector>
#include <fstream>
#include <stdexcept>
#include <filesystem>

#include "../inc/vault.hpp"
#include "../inc/cryptoutils.hpp"

#define CRYPTO_OFFSET 40 // the size of the MAC and nonce in ciphertext (16 + 24)


namespace fs = std::filesystem;

void write_bytes(const std::vector<unsigned char>& bytes, std::ofstream& out_file){
    for (int i = 0; i < bytes.size(); i++)
        out_file << bytes[i];
}

// encrypts a the given path and stores it to the target file 
void Vault::seal(const std::string& target, const std::string& password, const std::string& out_file){
    // ensure the path exists
    if (!fs::exists(target))
        throw std::runtime_error("cannot encrypt " + target + ", does it exist?");
    // generate a key from the given password
    Key master_key;
    gen_salt(master_key.salt);
    master_key.key = gen_key(password, master_key.salt);
    this->key_stack.push(master_key);
    // create the encrypted file
    std::ofstream out(out_file);
    write_bytes(master_key.salt, out);
    this->encrypt_file(target, out);
    out.close();

}

// encrypts the given file/directory. If it's a directory, this recursively encrypts the children. Writes the ciphertext to the file stream
void Vault::encrypt_file(const std::string& file_path, std::ofstream& out){
    Key parent_key = this->key_stack.top();
    Key new_key;
    gen_salt(new_key.salt);
    new_key.key = hash_key(parent_key.key, new_key.salt); 
    if (fs::is_directory(file_path)){
        this->key_stack.push(new_key);
        // write the directory header to the file
        unsigned char* tmp = (unsigned char*) file_path.c_str();
        std::vector<unsigned char> ciphertext;
        encrypt(std::vector(tmp, tmp + file_path.size()), new_key.key, ciphertext);
        out << BEGIN_DIR;
        write_bytes(new_key.salt, out);
        write_bytes(ciphertext, out);
        out << NULL_TERM;
        // write the contents of the directory to the file
        for (const auto &entry : fs::directory_iterator(file_path))
            this->encrypt_file(entry.path(), out);
        // end the diretory 
        out << END_DIR;
        this->key_stack.pop();
    }
    else{
        // encrypt the size of the file 
        unsigned long long file_size = fs::file_size(file_path);
        unsigned char size_buf[8];
        for (int i = 0; i < 8; i++){
            size_buf[i] = (file_size >> (i * 8)) & 0xFF;
        }
        std::vector<unsigned char> size_ciphertext;
        encrypt(std::vector<unsigned char>(size_buf, size_buf + 8), new_key.key, size_ciphertext);
        // write the file header to the file
        unsigned char* tmp = (unsigned char*) file_path.c_str();
        std::vector<unsigned char> path_ciphertext;
        encrypt(std::vector(tmp, tmp + file_path.size()), new_key.key, path_ciphertext);
        out << BEGIN_FILE;
        write_bytes(new_key.salt, out);
        write_bytes(path_ciphertext, out);
        out << NULL_TERM;
        write_bytes(size_ciphertext, out);
        out << NULL_TERM;
        // read and encrypt the file
        std::vector<unsigned char> file_content;
        std::ifstream in(file_path);
        char chr;
        while (in.get(chr))
            file_content.push_back(chr);
        in.close();
        std::vector<unsigned char> file_ciphertext;
        encrypt(file_content, new_key.key, file_ciphertext);
        out << &file_ciphertext[0];
        // store the encrypted file 
        write_bytes(file_ciphertext, out);
    }
}