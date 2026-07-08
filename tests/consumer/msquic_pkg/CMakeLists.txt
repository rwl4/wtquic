cmake_minimum_required(VERSION 3.24)
project(wtq_consumer_msquic LANGUAGES C)

find_package(wtquic REQUIRED COMPONENTS msquic)

add_executable(app main.c)
target_link_libraries(app PRIVATE wtq::msquic)
