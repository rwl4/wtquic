cmake_minimum_required(VERSION 3.20)
project(wtq_network_consumer C)

find_package(wtquic REQUIRED COMPONENTS network)

add_executable(consumer main.c)
target_link_libraries(consumer PRIVATE wtq::network)
set_target_properties(consumer PROPERTIES C_STANDARD 99
    C_STANDARD_REQUIRED ON)

add_executable(consumer_cxx main.cpp)
target_link_libraries(consumer_cxx PRIVATE wtq::network)
set_target_properties(consumer_cxx PROPERTIES CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON)
enable_language(CXX)
