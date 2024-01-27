cmake_minimum_required(VERSION 3.5)
project(smcryptoxx)

set(CMAKE_MACOSX_RPATH 1)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

find_path(GMP_HEADER_PATH gmp.h)
include_directories(include ${GMP_HEADER_PATH})

set(CMAKE_FIND_LIBRARY_SUFFIXES ".a;.so")
find_library(GMP_LIB_STATIC_PATH gmp)
find_library(M_LIB_STATIC_PATH m)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".so;.a")
find_library(GMP_LIB_SHARED_PATH gmp)
find_library(M_LIB_SHARED_PATH m)
add_library(smcryptoc_static STATIC src/sm3.c src/sm4.c src/sm2.c src/utils.c)
add_library(smcryptoc_shared SHARED src/sm3.c src/sm4.c src/sm2.c src/utils.c)
target_link_libraries(smcryptoc_static ${GMP_LIB_STATIC_PATH} ${M_LIB_STATIC_PATH})
target_link_libraries(smcryptoc_shared ${GMP_LIB_SHARED_PATH} ${M_LIB_SHARED_PATH})

set_target_properties(smcryptoc_static PROPERTIES OUTPUT_NAME smcryptoc)
set_target_properties(smcryptoc_shared PROPERTIES VERSION 1.0 SOVERSION 1 OUTPUT_NAME smcryptoc)

enable_testing()
add_subdirectory(tests)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/smcryptoc DESTINATION include)
install(TARGETS smcryptoc_static smcryptoc_shared ARCHIVE DESTINATION lib LIBRARY DESTINATION lib)
install(CODE "execute_process(COMMAND ldconfig)")