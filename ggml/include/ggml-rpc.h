#pragma once

#include "ggml-backend.h"
#include <functional>

// Peer credentials retrieved from Unix domain socket connections
// Uses SO_PEERCRED (Linux) to retrieve credentials
// On Windows/TCP connections: all fields are -1
struct ggml_rpc_peer_cred_t {
    int64_t pid;
    int64_t uid;
    int64_t gid;
};

#ifdef  __cplusplus
extern "C" {
#endif

#define RPC_PROTO_MAJOR_VERSION    3
#define RPC_PROTO_MINOR_VERSION    6
#define RPC_PROTO_PATCH_VERSION    0
#define GGML_RPC_MAX_SERVERS       16

// Callback type for verifying client connections
// Called after accept() for each new UDS connection
// Return true to allow the connection, false to reject it
using ggml_rpc_on_client_connect_t = std::function<bool(int sockfd, const ggml_rpc_peer_cred_t & cred)>;

// backend API
GGML_BACKEND_API ggml_backend_t ggml_backend_rpc_init(const char * endpoint, uint32_t device);
GGML_BACKEND_API bool ggml_backend_is_rpc(ggml_backend_t backend);

GGML_BACKEND_API ggml_backend_buffer_type_t ggml_backend_rpc_buffer_type(const char * endpoint, uint32_t device);

GGML_BACKEND_API void ggml_backend_rpc_get_device_memory(const char * endpoint, uint32_t device, size_t * free, size_t * total);

GGML_BACKEND_API void ggml_backend_rpc_start_server(const char * endpoint, const char * cache_dir,
                                                    size_t n_threads, size_t n_devices, ggml_backend_dev_t * devices,
                                                    std::function<void(void)> on_sock_create = nullptr,
                                                    ggml_rpc_on_client_connect_t on_client_connect = nullptr);

GGML_BACKEND_API ggml_backend_reg_t ggml_backend_rpc_reg(void);
GGML_BACKEND_API ggml_backend_reg_t ggml_backend_rpc_add_server(const char * endpoint);

#ifdef  __cplusplus
}
#endif
