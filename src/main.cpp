#include <iostream>
#include <sodium.h>
#include <filesystem>
#include <unistd.h>
#include <boost/program_options.hpp>

#include "../inc/vault.hpp"

#define PARSE_OUT_PATH(DEFAULT)\
out_path = (options.count("output_path") == 0) ? (DEFAULT) :  options["output_path"].as<std::string>()

#define ERROR_MSG(MSG)\
std::cerr << "\033[31merror:\033[0m " << MSG << std::endl


namespace fs = std::filesystem;
namespace po = boost::program_options;

enum COMMAND_CODES{ENCRYPT, DECRYPT, CHANGE_PW, HELP, VERSION};
std::map<std::string, int> command_map = {{"encrypt", ENCRYPT}, {"decrypt", DECRYPT}, {"change_password", CHANGE_PW}, {"help", HELP}, {"version", VERSION}};

int main(int argc, char** argv){
    // ensure sodium can be intialized
    if (sodium_init() != 0){
        ERROR_MSG("failed to initialize libsodium");
        return 1;
    }
    // parse user aguments
    po::options_description desc("NewVault");
    desc.add_options()
        ("command", po::value<std::string>(), "the command to be run. Valid options are: encrypt, decrypt and help")
        ("input_path", po::value<std::string>(), "the path of the directory or file to be encrypted OR the path of the vault file to be read if decrypting")
        ("output_path", po::value<std::string>(), "the path of the vault file to store encrypted files to OR the path to write the decrypted vault's contents to if decrypting")
    ;
    po::variables_map options;
    po::positional_options_description pos;
    pos.add("command", 1);
    pos.add("input_path", 1);
    pos.add("output_path", 1);
    auto parser = po::command_line_parser(argc, argv).options(desc).positional(pos).run();
    po::store(parser, options);
    // run the user's selected command
    if (!options.count("command")){
        ERROR_MSG("no command provided");
        return 1;
    }
    Vault vault;
    std::string command = options["command"].as<std::string>();
    int command_id = command_map.count(command) ? command_map[command] : -1;
    // parse the input path
    std::string input_path, out_path, password, confirm, old_path;
    if ((command_id != HELP && command_id != VERSION)){
        if (!options.count("input_path")){
                ERROR_MSG("no input path provided");
                return 1;
            }
            input_path = options["input_path"].as<std::string>();
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
            std::cout << desc << std::endl;
            break;
        case VERSION:
            std::cout << "NewVault version 0.1.2" << std::endl;
            break;
        default:
            ERROR_MSG("unrecognized command.\nProgram help:");
            std::cout << desc << std::endl;
    }
}
