#include <iostream>
#include <sodium.h>
#include <filesystem>
#include <unistd.h>
#include <map>

#include "../inc/vault.hpp"

#define PARSE_OUT_PATH(DEFAULT) out_path = (argc >= 4) ? argv[3] : DEFAULT
#define ERROR_MSG(MSG) std::cerr << "\033[31merror:\033[0m " << MSG << std::endl


namespace fs = std::filesystem;

enum COMMAND_CODES{ENCRYPT, DECRYPT, CHANGE_PW, HELP, VERSION};
std::map<std::string, int> command_map = {{"encrypt", ENCRYPT}, {"decrypt", DECRYPT}, {"change_password", CHANGE_PW}, {"help", HELP}, {"version", VERSION}};

void print_help(std::string command_name = ""){
    std::string commands[] = {"Command:", "  encrypt", "  decrypt", "  change_password", "  help", "  version"};
    std::string arguments[] = {"Arguments:", "  <input path> [archive path]", "  <archive path> [output path]", "  <archive path> [new archive path]", "  [command]", ""};
    std::string descriptions[] = {
        "Encrypts the contents in the input path, and creates an encrypted vault archive at the archive path, if no archive path is specified, an archive will be made in the current working directory",
        "Decrypts the contents of the vault archive and saves them to the output path, if no output path is specified, the decrypted contents will be saved to the current working directory.",
        "Creates a copy of the vault at archive_path and saves it with a new password to the new archive path, if the new path is not specified, this will change the password in place",
        "Displays this menu",
        "Displays the current version of newvault"
    };
    if (command_name == ""){
        std::cout << "NewVault Commands:" << std::endl;
        for (int i = 0; i < 6; i++)
            std::cout << "\t" << std::left << std::setw(24) << commands[i] << arguments[i] << std::endl;
    }
    else{
        if (command_map.count(command_name) == 0)
            std::cout << "unrecognized command" << std::endl;
        else{
            int command_code = command_map[command_name];
            std::cout << commands[command_code] <<  "    " << arguments[command_code] << "\n\t" << descriptions[command_code] << std::endl;
        }
    }
}

int main(int argc, char** argv){
    // ensure sodium can be intialized
    if (sodium_init() != 0){
        ERROR_MSG("failed to initialize libsodium");
        return 1;
    }
    // run the user's selected command
    if (argc < 2){
        ERROR_MSG("no command provided");
        return 1;
    }
    Vault vault;
    std::string command = argv[1];
    int command_id = command_map.count(command) ? command_map[command] : -1;
    // parse the input path
    std::string input_path, out_path, password, confirm, old_path;
    if ((command_id != HELP && command_id != VERSION)){
        if (argc < 3){
                ERROR_MSG("no input path provided");
                return 1;
            }
            input_path = argv[2];
    }
    // run the chosen command
    switch (command_id){
        case ENCRYPT:
            PARSE_OUT_PATH(static_cast<std::string>(fs::current_path()) + '/' + input_path + ".nva");
            if (out_path.substr(out_path.length() - 4) != ".nva")
                out_path += ".nva";
            password = getpass("Vault password: ");
            confirm = getpass("Confirm: ");
            if (password != confirm){
                ERROR_MSG("password does not match confirmation");
                return 1;
            }
            std::cout << "Encrypting..." << std::endl;
            try{
                vault.seal(input_path, out_path, password);
            }
            catch (std::runtime_error e){
                ERROR_MSG(e.what());
                return 1;
            }
            std::cout << "Completed" << std::endl;
            break;
        case DECRYPT:
            if (input_path.substr(input_path.length() - 4) != ".nva"){
                ERROR_MSG("invalid vault file.");
                return 1;
            }
            PARSE_OUT_PATH(static_cast<std::string>(fs::current_path()));
            password = getpass("Vault password: ");
            std::cout << "Decrypting..." << std::endl;
            try{
                vault.unseal(input_path, out_path, password);
            }
            catch (std::runtime_error e){
                fs::remove(out_path);
                ERROR_MSG(e.what());
                return 1;
            }
            std::cout << "Completed" << std::endl;
            break;
        case CHANGE_PW:
            if (input_path.substr(input_path.length() - 4) != ".nva"){
                ERROR_MSG("invalid vault file.");
                return 1;
            }
            PARSE_OUT_PATH(input_path);
            // decrypt the vault to a temporary directory
            password = getpass("Current password: ");
            try{
                vault.unseal(input_path, "TMP_VAULT", password);
            }
            catch (std::runtime_error e){
                fs::remove_all("TMP_VAULT");
                ERROR_MSG(e.what());
                return 1;
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
                ERROR_MSG("New password does not match confirmation");
                fs::current_path("..");
                fs::remove_all("TMP_VAULT");
                return 1;
            }
            try{
                vault.seal(old_path, "../"+out_path, password);
            }
            catch (std::runtime_error e){
                ERROR_MSG(e.what());
                return 1;
            }
            fs::current_path("..");
            fs::remove_all("TMP_VAULT");
            break;
        case HELP:
            command = (argc >= 3) ? argv[2] : "";
            print_help(command);
            break;
        case VERSION:
            std::cout << "NewVault version 0.1.3" << std::endl;
            break;
        default:
            ERROR_MSG("unrecognized command.\nProgram help:");
            print_help();
    }
}
