project("ZFileReadOnlyFile_in_C")
cmake_minimum_required(VERSION 2.6)


#set(CMAKE_LINK_FLAGS "${CMAKE_LINK_FLAGS} -fprofile-instr-generate")

if (CMAKE_BUILD_TYPE STREQUAL "Release")
	add_compile_options("-O3")
else()
	add_compile_options("-g")
	add_compile_options("-O0")
endif()

message("BUILD_TYPE: ${CMAKE_BUILD_TYPE}")

include_directories("./")
include_directories("../")

add_executable(zfile_ro zfile_decompress.c lz4.c)

set(SRC_LIST zfile_ro_file.c
)


