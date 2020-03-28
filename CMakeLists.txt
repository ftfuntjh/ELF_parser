cmake_minimum_required(VERSION 3.10.2)
project(ELF_Parser)
set_property(GLOBAL PROPERTY C_STANDARD 98)
add_executable(ELF_Parser ./src/ELF_Parser.c ./src/ELF_Static.c)


