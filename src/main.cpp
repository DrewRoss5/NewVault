#include <iostream>
#include <sodium.h>
#include <filesystem>
#include <unistd.h>
#include <map>

#include "../inc/vault.hpp"

#define KEY_SIZE 64

#define PARSE_OUT_PATH(DEFAULT) out_path = (argc >= 4) ? argv[3] : DEFAULT
#define ERROR_CRASH(MSG) \
    {\
        std::cerr << "\033[31merror:\033[0m " << MSG << std::endl;\
        return 1;\
    }


namespace fs = std::filesystem;

enum COMMAND_CODES{ENCRYPT, DECRYPT, CHANGE_PW, EXPORT_KEY, IMPORT, HELP, VERSION};
std::map<std::string, int> command_map = {{"encrypt", ENCRYPT}, {"decrypt", DECRYPT}, {"change_password", CHANGE_PW}, {"export_key", EXPORT_KEY}, {"import", IMPORT}, {"help", HELP}, {"version", VERSION}};

void print_help(std::string command_name = ""){
    std::string commands[] = {"Command:", "  encrypt", "  decrypt", "  change_password", "  export_key", "  import", "  help", "  version"};
    std::string arguments[] = {"Arguments:", "  <input path> [archive path]", "  <archive path> [output path]", "  <archive path> [new archive path]", "  <archive path> [key path]", "  <archive path> [output path]", "  [command]", ""};
    std::string descriptions[] = { "",
        "Encrypts the contents in the input path, and creates an encrypted vault archive at the archive path, if no archive path is specified, an archive will be made in the current working directory",
        "Decrypts the contents of the vault archive and saves them to the output path, if no output path is specified, the decrypted contents will be saved to the current working directory.",
        "Creates a copy of the vault at archive_path and saves it with a new password to the new archive path, if the new path is not specified, this will change the password in place",
        "Exports the master key for the the provided archive, and saves it to the key path. If no key path is provided, this will simply write the key to the terminal",
        "Works like the decrypt command, but accepts a 256-bit hex-encoded key instead of a regular password",
        "Displays this menu",
        "Displays the current version of newvault"
    };
    if (command_name == ""){
        std::cout << "NewVault Commands:" << std::endl;
        for (int i = 0; i < 8; i++)
            std::cout << "\t" << std::left << std::setw(24) << commands[i] << arguments[i] << std::endl;
    }
    else{
        if (command_map.count(command_name) == 0)
            std::cout << "unrecognized command" << std::endl;
        else{
            int command_code = command_map[command_name] + 1;
            std::cout << commands[command_code] <<  "    " << arguments[command_code] << "\n\t" << descriptions[command_code]<< std::endl;
        }
    }
}

int main(int argc, char** argv){
    // ensure sodium can be intialized
    if (sodium_init() != 0)
        ERROR_CRASH("libsodium could not be intialize")
    // run the user's selected command
    if (argc < 2)
        ERROR_CRASH("no command provided")
    Vault vault;
    std::string command = argv[1];
    int command_id = command_map.count(command) ? command_map[command] : -1;
    // parse the input path
    std::string input_path, out_path, password, confirm, old_path, master_key, key_str;
    if ((command_id != -1 && command_id != HELP && command_id != VERSION)){
        if (argc < 3)
            ERROR_CRASH("no input path provided")
        input_path = argv[2];
    }
    // run the chosen command
    std::ofstream out;
    std::ifstream in;
    Key file_key;
    std::vector<unsigned char> key_bytes, key_salt;
    char salt_str[33];
    switch (command_id){
        case ENCRYPT:
            PARSE_OUT_PATH(static_cast<std::string>(fs::current_path()) + '/' + input_path + ".nva");
            if (out_path.substr(out_path.length() - 4) != ".nva")
                out_path += ".nva";
            password = getpass("Vault password: ");
            confirm = getpass("Confirm: ");
            if (password != confirm)
                ERROR_CRASH("password does match confirmation");
            std::cout << "Encrypting..." << std::endl;
            try{
                vault.seal(input_path, out_path, password);
            }
            catch (std::runtime_error e)
                ERROR_CRASH(e.what());
            std::cout << "Completed" << std::endl;
            break;
        case DECRYPT:
            if (input_path.substr(input_path.length() - 4) != ".nva")
                ERROR_CRASH("invalid vault file")
            PARSE_OUT_PATH(static_cast<std::string>(fs::current_path()));
            password = getpass("Vault password: ");
            std::cout << "Decrypting..." << std::endl;
            try{
                vault.unseal(input_path, out_path, password);
            }
            catch (std::runtime_error e){
                fs::remove(out_path);
                ERROR_CRASH(e.what())
            }
            std::cout << "Completed" << std::endl;
            break;
        case CHANGE_PW:
            if (input_path.substr(input_path.length() - 4) != ".nva")
                ERROR_CRASH("invalid vault file")
            PARSE_OUT_PATH(input_path);
            // decrypt the vault to a temporary directory
            password = getpass("Current password: ");
            try{
                vault.unseal(input_path, "TMP_VAULT", password);
            }
            catch (std::runtime_error e){
                fs::remove_all("TMP_VAULT");
                ERROR_CRASH(e.what());
            }
            // get the name of the originally encryptd path
            fs::current_path("TMP_VAULT");
            for (auto& tmp : fs::directory_iterator(fs::current_path())){
                old_path = tmp.path();
                break; // this should have only one item in it so there's no need to loop again
            }
            // re-encrypt thee vault with a new password
            password = getpass("New vault password: ");
            confirm = getpass("Confrim new password: ");
            if (password != confirm){
                fs::current_path("..");
                fs::remove_all("TMP_VAULT");
                ERROR_CRASH("new password does not match confirmation");
            }
            try{
                vault.seal(old_path, "../"+out_path, password);
            }
            catch (std::runtime_error e)
                ERROR_CRASH(e.what());
            fs::current_path("..");
            fs::remove_all("TMP_VAULT");
            break;
        case EXPORT_KEY:
            if (input_path.substr(input_path.length() - 4) != ".nva") 
                ERROR_CRASH("invalid vault file");
            password = getpass("Password: ");
            try{
                master_key = vault.export_master_key(input_path, password);
                if (argc >= 4){
                    std::ofstream(argv[3]) << master_key;
                    std::cout << "Key exported" << std::endl;
                }
                else
                    std::cout << master_key << std::endl;
            }
            catch (std::runtime_error e) 
                ERROR_CRASH(e.what());
            break;
        case IMPORT:
            std::cout << input_path << std::endl;
            if (input_path.substr(input_path.length() - 4) != ".nva")   
                ERROR_CRASH("invalid vault file");
            PARSE_OUT_PATH(static_cast<std::string>(fs::current_path()));
            key_str = getpass("File key: ");
            try{
                if(key_str.size() != KEY_SIZE)
                    throw std::runtime_error("");
                store_hex(key_str, key_bytes);
            }
            catch (...)
                ERROR_CRASH("invalid file key");
            in = std::ifstream(input_path);
            if (!in.good())
                ERROR_CRASH("input file could not be found");
            parse_hex_str(in, file_key.salt, 32);
            try{
                std::cout << "Decrypting..." << std::endl;
                file_key.key = key_bytes;
                vault.unseal(in, out_path, file_key);
                std::cout << "Completed" << std::endl;
            }
            catch (std::runtime_error e)
                ERROR_CRASH(e.what());
            break;
        case HELP:
            command = (argc >= 3) ? argv[2] : "";
            print_help(command);
            break;
        case VERSION:
            std::cout << "NewVault version 0.1.4" << std::endl;
            break;
        default:
            std::cerr << "\033[31merror:\033[0m unrecognized command" << std::endl;
            print_help();
    }
    return 0;
}