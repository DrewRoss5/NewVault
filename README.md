# NewVault
### About: 
NewVault is a free and open-sourced directory encryption tool written in C++. Currently, NewVault is built meant for Unix-based systems, however, additional support for Windows may be added in the future. 
#### ⚠️ WARNING ⚠️
While NewVault uses LibSodium for cryptographic primatives, and currently has no known vulnerabilites, it has not professionally audited for security and may have unknown vulnerabilities. **Use this tool at your own risk.**


### Roadmap / ToDo
- Add more robust error handling
- Add key exporting/importing functionality
- Improve Windows compatibility
- Switch from Hex formatting to Base64


# Building/Installation:
To install NewVault on a Linux system, first, ensure that [CMake](https://cmake.org/download/) and [Boost](https://www.boost.org/doc/libs/1_56_0/more/getting_started/unix-variants.html) are installed.<br>
Once the prerequisites are installed, clone this repo and run the following commands:
- `mkdir build`
- `cd build`
- `cmake ..`
- `make`
  
This will create a standalone `newvault` binary. Optionally, you may copy this binary to the path `/usr/bin/newvault` for convenient access. 

# Usage:
There are currently three supported commands:
#### `newvault encrypt <in_path> [archive_path]`
- Creates a password-encrypted vault archive of `in_path` and stores it to `archive_path`. If no archive path is specified, the vault file will have the same name as `in_path` and will be stored in the current working directory.
- While the intended use case of this command is to encrypt directories and all of their contents, this command can additionally be used to encrypt standalone files, if so desired.
- **Important:** When prompted for a vault password, ensure you have either memorized the password or stored it somewhere, as there is currently no way to access a vault file without the original password, and passwords cannot be changed.
#### `newvault decrypt <archive_path> [out_path]`
- Decrypts a vault archive and stores the decrypted contents to `out_path`.
- If `out_path` is not specified the vault's content will simply be stored to the current working directory. 
#### `newvault help`
- Displays the help menu
