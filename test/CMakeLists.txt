add_executable(run_tests
    tests.c
)

target_link_libraries(run_tests
    hashing_static
    unity
)

add_test(NAME test_suite COMMAND $<TARGET_FILE:run_tests>)