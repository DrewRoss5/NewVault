#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sodium.h>

#include "../inc/cryptoutils.hpp"

// converts an unsigned char vector to a hex string
std::string hex_string(const std::vector<unsigned char>& bytes){
    std::stringstream ss;
    for (int i = 0; i < bytes.size(); i++)
        ss << std::setw(2) <<std::hex <<std::setfill('0') << (int)  bytes[i];
    return ss.str();
}

// displays an error message
void error_msg(std::string msg){
    std::cout << "\033[31merror:\033[0m " << msg << std::endl;
}

int main(int argc, char** argv){
    // ensure sodium insitalizes properly
    if (sodium_init() != 0){
        error_msg("failed to initialize libsodium");
        return 1;
    }
    // test key generation
    std::vector<unsigned char> salt, second_salt;
    gen_salt(salt);
    std::vector<unsigned char> key = gen_key("TestPassword123!", salt);
    std::cout << "Salt: " << hex_string(salt) << "\nKey: " << hex_string(key) << std::endl;
    // test encryption/decryption
    unsigned char* tmp = (unsigned char*) "The british are coming!";
    std::vector<unsigned char> plaintext(tmp, tmp + 24);
    std::vector<unsigned char> ciphertext, decrypted;
    std::cout << "Encrypting..." << std::endl;
    encrypt(plaintext, key, ciphertext);
    std::cout << "Ciphertext: " << hex_string(ciphertext) << std::endl;
     try{
        decrypt(ciphertext, key, decrypted);
        std::cout << decrypted.size() << std::endl;
        std::cout << "Decrypted: " <<  &plaintext[0] << std::endl;
    }
    catch (std::runtime_error e){
        error_msg(e.what());
    }
}