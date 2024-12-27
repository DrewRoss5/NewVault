#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sodium.h>

#include "../inc/cryptoutils.hpp"

// displays an error message
void error_msg(std::string msg){
    std::cout << "\033[31merror:\033[0m " << msg << std::endl;
}

// converts an unsigned char array to a hex string
std::string hex_string(const std::vector<unsigned char>& bytes){
    std::stringstream ss;
    for (int i = 0; i < bytes.size(); i++)
        ss << std::setw(2) <<std::hex <<std::setfill('0') << (int)  bytes[i];
    return ss.str();
}

int main(int argc, char** argv){
    // ensure sodium insitalizes properly
    if (sodium_init() != 0){
        error_msg("failed to initialize libsodium");
        return 1;
    }
    // run the application
    std::vector<unsigned char> salt;
    gen_salt(salt);
    std::vector<unsigned char> key = gen_key("TestPassword123!", salt);
    std::cout << "Salt: " << hex_string(salt) << "\nKey: " << hex_string(key) << std::endl;
}