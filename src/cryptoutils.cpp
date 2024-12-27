#include <vector>
#include <string>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_hash_sha256.h>
#include <sodium/randombytes.h>

#include "../inc/cryptoutils.hpp"

#define SALT_SIZE 16
#define KEY_SIZE 32

// generate a random salt and writes it to the the given buffer
void gen_salt(std::vector<unsigned char>& salt){
    salt.resize(SALT_SIZE);
    randombytes_buf(&salt[0], SALT_SIZE);
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

// hashes a key with a salt 
std::vector<unsigned char> hash_key(const std::vector<unsigned char>& key, const std::vector<unsigned char>& salt){
    // hash the old key
    crypto_hash_sha256_state key_hash;
    crypto_hash_sha256_init(&key_hash);
    crypto_hash_sha256_update(&key_hash, &key[0], KEY_SIZE);
    crypto_hash_sha256_update(&key_hash, &salt[0], SALT_SIZE);
    // read the new key to a buffer
    std::vector<unsigned char> new_key;
    new_key.resize(32);
    crypto_hash_sha256_final(&key_hash, &new_key[0]);
    return new_key;
}

// encrypts a plaintext with a 32-byte key
void encrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key, std::vector<unsigned char>& ciphertext){
    unsigned message_len = plaintext.size();
    // genereate a nonce
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
    // encrypt the plaintext and store it to the ciphertext buffer
    ciphertext.resize(message_len + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES);
    crypto_secretbox_easy(&ciphertext[0], &plaintext[0], message_len, nonce, &key[0]);
    // append the nonce to the ciphertext
    std::memcpy(&ciphertext[message_len + crypto_secretbox_MACBYTES], nonce, crypto_secretbox_NONCEBYTES);
}   

// decrypts a ciphertext with a 32-byte key
void decrypt(std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, std::vector<unsigned char>& plaintext){
    unsigned ciphertext_size = ciphertext.size() - crypto_secretbox_NONCEBYTES;
    // seperate the nonce from the ciphertext
    unsigned char* nonce = &ciphertext[ciphertext_size];
    // decrypt the ciphertext and store it to the plaintext buffer
    plaintext.resize(ciphertext_size  - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(&plaintext[0], &ciphertext[0], ciphertext_size, nonce, &key[0]) != 0)
        throw std::runtime_error("failed to decrypt ciphertext");
}