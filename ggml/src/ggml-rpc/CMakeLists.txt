message(STATUS "Using RPC backend")

ggml_add_backend_library(ggml-rpc
                         ggml-rpc.cpp
                        )

if (WIN32)
    target_link_libraries(ggml-rpc PRIVATE ws2_32)
endif()

if (NOT MSVC)
    if (GGML_SANITIZE_FUZZER)
        target_compile_definitions(ggml-rpc PUBLIC GGML_SANITIZE_FUZZER=1)
    endif()
endif()