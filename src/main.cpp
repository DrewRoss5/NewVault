#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sodium.h>
#include <unistd.h>

#include "../inc/vault.hpp"

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
    std::cout << "Path to encrypt: " << std::flush;
    std::string input_path;
    std::getline(std::cin, input_path);
    std::string password = getpass("Password: ");
    std::string confirm = getpass("Confirm: ");
    if (password != confirm){
        error_msg("password does not match confirmation");
        return 1;
    }
    std::string output_path;
    std::cout << "Archive path: " << std::flush;
    std::getline(std::cin, output_path);
    std::cout << "Encrypting..." << std::endl;
    Vault vault;
    vault.seal(input_path, output_path, password);
    std::cout << "Encrypted" << std::endl;
}