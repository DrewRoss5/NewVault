cmake_minimum_required(VERSION 3.28)

project(NewVault VERSION 0.1.0)

# set directory varaiables 
set(SOURCE_DIR "src/")
set(INC_DIR "inc/")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# include boost program options
find_package(Boost 1.83 COMPONENTS program_options REQUIRED)
# include libsodium
find_package(Sodium REQUIRED)

add_executable(newvault ${SOURCE_DIR}main.cpp ${SOURCE_DIR}cryptoutils.cpp ${SOURCE_DIR}vault.cpp ${INC_DIR}cryptoutils.hpp ${INC_DIR}vault.hpp)
target_link_libraries(newvault Boost::program_options)
target_link_libraries(newvault sodium)