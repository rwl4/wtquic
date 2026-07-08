cmake_minimum_required(VERSION 3.20)
project(wtq_embed_full C)

# wtquic embedded as a subproject: its packaging files must land inside
# ITS OWN project/build directories, never the superproject's.
add_subdirectory(${WTQ_SOURCE_DIR} wtquic)

add_executable(embed_consumer main.c)
target_link_libraries(embed_consumer PRIVATE wtq::network)
