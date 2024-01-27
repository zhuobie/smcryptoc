add_executable(test_sm2_static test_sm2.c)
add_executable(test_sm3_static test_sm3.c)
add_executable(test_sm4_static test_sm4.c)

add_executable(test_sm2_shared test_sm2.c)
add_executable(test_sm3_shared test_sm3.c)
add_executable(test_sm4_shared test_sm4.c)

target_link_libraries(test_sm2_static smcryptoc_static)
target_link_libraries(test_sm3_static smcryptoc_static)
target_link_libraries(test_sm4_static smcryptoc_static)

target_link_libraries(test_sm2_shared smcryptoc_shared)
target_link_libraries(test_sm3_shared smcryptoc_shared)
target_link_libraries(test_sm4_shared smcryptoc_shared)

include(CTest)

add_test(NAME test_sm2_static COMMAND test_sm2_static)
add_test(NAME test_sm3_static COMMAND test_sm3_static)
add_test(NAME test_sm4_static COMMAND test_sm4_static)

add_test(NAME test_sm2_shared COMMAND test_sm2_shared)
add_test(NAME test_sm3_shared COMMAND test_sm3_shared)
add_test(NAME test_sm4_shared COMMAND test_sm4_shared)