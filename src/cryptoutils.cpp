#include <vector>
#include <string>
#include <cstring>
#include <iostream>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_hash_sha256.h>
#include <sodium/randombytes.h>

#include "../inc/cryptoutils.hpp"

#define SALT_SIZE 16

// generate a random salt and writes it to the the given buffer
void gen_salt(std::vector<unsigned char>& salt){
    unsigned char* seed;
    salt.resize(SALT_SIZE);
}

// generates a key from a string passowrd using a sha-256 hash (this assumes the salt's size has already been validated)
std::vector<unsigned char> gen_key(const std::string& password, const std::vector<unsigned char>& salt){
    // convert the string to an unsigned char array
    unsigned pw_size = password.size();
    unsigned char* pw_arr = new unsigned char[pw_size];
    std::memcpy(pw_arr, password.c_str(), password.size());
    // hash the key
    crypto_hash_sha256_state key_hash;
    crypto_hash_sha256_init(&key_hash);
    crypto_hash_sha256_update(&key_hash, pw_arr, password.size());
    crypto_hash_sha256_update(&key_hash, &salt[0], SALT_SIZE);
    // read the key to a buffer
    std::vector<unsigned char> key;
    key.resize(32);
    crypto_hash_sha256_final(&key_hash, &key[0]);
    delete[] pw_arr;
    return key;

}