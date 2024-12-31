#include <iostream>
#include <sodium.h>
#include <filesystem>
#include <unistd.h>
#include <boost/program_options.hpp>

#include "../inc/vault.hpp"

#define COMMAND_COUNT 4
#define PARSE_OUT_PATH(DEFAULT)\
out_path = (options.count("output_path") == 0) ? (DEFAULT) :  options["output_path"].as<std::string>();

namespace fs = std::filesystem;
namespace po = boost::program_options;

enum COMMAND_CODES{ENCRYPT, DECRYPT, HELP, VERSION};
std::string commands[] = {"encrypt", "decrypt", "help", "version"};

// displays an error message
void error_msg(std::string msg){
    std::cerr << "\033[31merror:\033[0m " << msg << std::endl;
}

int main(int argc, char** argv){
    // ensure sodium can be intialized
    if (sodium_init() != 0){
        error_msg("failed to initialize libsodium");
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
        error_msg("no command provided");
        return 1;
    }
    Vault vault;
    std::string command = options["command"].as<std::string>();
    std::map<std::string, int> command_map = {{"encrypt", ENCRYPT}, {"decrypt", DECRYPT}, {"help", HELP}, {"version", VERSION}};
    int command_id = command_map.count(command) ? command_map[command] : -1;
    // parse the input path
    std::string input_path, out_path, password, confirm;
    if ((command_id == ENCRYPT || command_id == DECRYPT)){
        if (!options.count("input_path")){
                error_msg("no input path provided");
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
            password = getpass("Vault Password: ");
            confirm = getpass("Confirm: ");
            if (password != confirm){
                error_msg("password does not match confirmation");
                return 1;
            }
            std::cout << "Encrypting..." << std::endl;
            try{
                vault.seal(input_path, out_path, password);
            }
            catch (std::runtime_error e){
                error_msg(e.what());
                return 1;
            }
            std::cout << "Completed" << std::endl;
            break;
        case DECRYPT:
            if (input_path.substr(input_path.length() - 4) != ".nva"){
                error_msg("invalid vault file.");
                return 1;
            }
            PARSE_OUT_PATH(static_cast<std::string>(fs::current_path()));
            password = getpass("Vault Password: ");
            std::cout << "Decrypting..." << std::endl;
            try{
                vault.unseal(input_path, out_path, password);
            }
            catch (std::runtime_error e){
                error_msg(e.what());
                return 1;
            }
            std::cout << "Completed" << std::endl;
            break;
        case HELP:
            std::cout << desc << std::endl;
            break;
        case VERSION:
            std::cout << "NewVault version 0.1.1" << std::endl;
            break;
        default:
            error_msg("unrecognized command.\nProgram help:");
            std::cout << desc << std::endl;
    }
}
