set(TARGET rpc-server)
add_executable(${TARGET} rpc-server.cpp)

if (NOT MSVC)
    if (GGML_SANITIZE_FUZZER)
        target_compile_definitions(rpc-server PUBLIC GGML_SANITIZE_FUZZER=1)
    endif()
endif()

target_link_libraries(${TARGET} PRIVATE ggml)
target_compile_features(${TARGET} PRIVATE cxx_std_17)
