#include "ggml-rpc.h"
#ifdef _WIN32
#  define NOMINMAX
#  define DIRECTORY_SEPARATOR '\\'
#  include <windows.h>
#  include <fcntl.h>
#  include <io.h>
#else
#  define DIRECTORY_SEPARATOR '/'
#  include <unistd.h>
#  include <sys/stat.h>
#  include <climits>
#endif
#include <string>
#include <stdio.h>
#include <vector>
#include <set>
#include <filesystem>
#include <algorithm>
#include <thread>
#include <regex>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <fstream>

#if defined(__linux__)
#include <seccomp.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#endif

#if defined(__linux__)
#include <sys/types.h>
#include <pwd.h>
#endif

// NOTE: this is copied from common.cpp to avoid linking with libcommon
#ifdef _WIN32
static std::wstring utf8_to_wstring(const std::string & str) {
    if (str.empty()) {
        return std::wstring();
    }

    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), NULL, 0);

    if (size <= 0) {
        return std::wstring();
    }

    std::wstring wstr(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &wstr[0], size);

    return wstr;
}
#endif

#if defined(__linux__)
static void install_rlimits(bool use_cache) {
    struct rlimit rl;
    rl.rlim_cur = 64;
    rl.rlim_max = 64;

    if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
        fprintf(stderr, "Warning: Failed to set RLIMIT_NOFILE: %s\n", strerror(errno));
    }

    rl.rlim_cur = 0;
    rl.rlim_max = 0;

    if (setrlimit(RLIMIT_NPROC, &rl) < 0) {
        fprintf(stderr, "Warning: Failed to set RLIMIT_NPROC: %s\n", strerror(errno));
    }

    if (use_cache == true) {
        fprintf(stderr, "Skipping setting RLIMIT_FSIZE due to cache usage\n");
    } else {
        if (setrlimit(RLIMIT_FSIZE, &rl) < 0) {
            fprintf(stderr, "Warning: Failed to set RLIMIT_FSIZE: %s\n", strerror(errno));
        }
    }

    fprintf(stdout, "Resource limits installed\n");
}

static void install_chroot() {
    if (geteuid() != 0) {
        fprintf(stdout, "Skipping chroot (requires root privileges)\n");
        return;
    }

    const char * jail_path = "/tmp/secure-ggml-rpc-jail";

    if (mkdir(jail_path, 0755) < 0 && errno != EEXIST) {
        fprintf(stderr, "Warning: Failed to create chroot jail directory: %s\n", strerror(errno));
        return;
    }

    if (chroot(jail_path) < 0) {
        fprintf(stderr, "Warning: Failed to chroot: %s\n", strerror(errno));
        return;
    }

    if (chdir("/") < 0) {
        fprintf(stderr, "Warning: Failed to chdir after chroot: %s\n", strerror(errno));
        return;
    }

    fprintf(stdout, "Chroot jail installed at %s\n", jail_path);
}

static void install_no_new_privs() {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        fprintf(stderr, "Warning: Failed to set PR_SET_NO_NEW_PRIVS: %s\n", strerror(errno));
        return;
    }

    fprintf(stdout, "PR_SET_NO_NEW_PRIVS installed\n");
}

static void install_seccomp_filter() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) {
        fprintf(stderr, "Failed to create seccomp filter %s\n", strerror(errno));
        exit(1);
    }

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept4), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sysinfo), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mremap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone3), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rseq), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getaffinity), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_yield), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(tgkill), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prlimit64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrlimit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ppoll), 0);

    if (seccomp_load(ctx) < 0) {
        fprintf(stderr, "Failed to load seccomp filter %s\n", strerror(errno));
        exit(1);
    } else {
        fprintf(stdout, "Seccomp filter installed\n");
    }

    seccomp_release(ctx);
}

struct rpc_policy {
    // Allowed UIDs (empty = allow all)
    std::set<int64_t> allowed_uids;
    // Allowed GIDs (empty = allow all)
    std::set<int64_t> allowed_gids;
    // Allowed executable paths (empty = allow all)
    // Verified via /proc/PID/exe
    std::set<std::string> allowed_exes;
    // Whether to allow root (UID 0) regardless of allowed_uids
    bool allow_root = true;
    // Log all connection attempts (including rejected)
    bool log_connections = true;
};

// Read the executable path for a given PID via /proc/PID/exe
// Returns an empty string on failure
static std::string get_exe_path_for_pid(int64_t pid) {
    if (pid <= 0) {
        return "";
    }

    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%lld/exe", (long long)pid);

    char exe_path[PATH_MAX];
    ssize_t len = readlink(proc_path, exe_path, sizeof(exe_path) - 1);

    if (len <= 0) {
        fprintf(stderr, "[policy] Failed to read %s: %s\n", proc_path, strerror(errno));
        return "";
    }

    exe_path[len] = '\0';

    // Handle 'deleted' executables
    const char *deleted_suffix = " (deleted)";
    size_t suffix_len = strlen(deleted_suffix);

    if (len > (ssize_t)suffix_len &&
        strcmp(exe_path + len - suffix_len, deleted_suffix) == 0) {
        exe_path[len - suffix_len] = '\0';
    }

    return std::string(exe_path);
}

static bool verify_peer_credentials(const rpc_policy & policy, const ggml_rpc_peer_cred_t & cred) {
    // Check if root bypass is enabled
    if (policy.allow_root && cred.uid == 0) {
        if (policy.log_connections) {
            fprintf(stdout, "[policy] Allowing root connection (uid=0, pid=%lld)\n",
                    (long long)cred.pid);
        }
        return true;
    }

    // Check UID allowlist
    if (!policy.allowed_uids.empty() && policy.allowed_uids.find(cred.uid) == policy.allowed_uids.end()) {
        fprintf(stderr, "[policy] Rejected: UID %lld not in allowlist\n",
                (long long)cred.uid);
        return false;
    }

    // Check GID allowlist
    if (!policy.allowed_gids.empty() && policy.allowed_gids.find(cred.gid) == policy.allowed_gids.end()) {
        fprintf(stderr, "[policy] Rejected: GID %lld not in allowlist\n",
                (long long)cred.gid);
        return false;
    }

    if (!policy.allowed_exes.empty()) {
        if (cred.pid <= 0) {
            fprintf(stderr, "[policy] Rejected: Cannot verify executable (no PID available)\n");
            return false;
        }

        std::string exe_path = get_exe_path_for_pid(cred.pid);
        if (exe_path.empty()) {
            fprintf(stderr, "[policy] Rejected: Could not read executable path for PID %lld\n",
                    (long long)cred.pid);
            return false;
        }

        if (policy.allowed_exes.find(exe_path) == policy.allowed_exes.end()) {
            fprintf(stderr, "[policy] Rejected: Executable '%s' not in allowlist\n",
                    exe_path.c_str());
            return false;
        }

        if (policy.log_connections) {
            fprintf(stdout, "[policy] Verified executable: %s\n", exe_path.c_str());
        }
    }

    if (policy.log_connections) {
        fprintf(stdout, "[policy] Accepted connection: uid=%lld, gid=%lld, pid=%lld\n",
                (long long)cred.uid, (long long)cred.gid, (long long)cred.pid);
    }

    return true;
}

// ============================================================================
// Policy file parsing
// ============================================================================

static std::string trim(const std::string & str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

static bool parse_policy_file(const std::string & path, rpc_policy & policy, struct rpc_server_params & params);

static bool apply_policy_directive(const std::string & key, const std::string & value,
                                   rpc_policy & policy, struct rpc_server_params & params);
#endif

// NOTE: this is copied from common.cpp to avoid linking with libcommon
// returns true if successful, false otherwise
static bool fs_create_directory_with_parents(const std::string & path) {
#ifdef _WIN32
    std::wstring wpath = utf8_to_wstring(path);

    // if the path already exists, check whether it's a directory
    const DWORD attributes = GetFileAttributesW(wpath.c_str());
    if ((attributes != INVALID_FILE_ATTRIBUTES) && (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        return true;
    }

    size_t pos_slash = 0;

    // process path from front to back, procedurally creating directories
    while ((pos_slash = path.find('\\', pos_slash)) != std::string::npos) {
        const std::wstring subpath = wpath.substr(0, pos_slash);

        pos_slash += 1;

        // skip the drive letter, in some systems it can return an access denied error
        if (subpath.length() == 2 && subpath[1] == ':') {
            continue;
        }

        const bool success = CreateDirectoryW(subpath.c_str(), NULL);

        if (!success) {
            const DWORD error = GetLastError();

            // if the path already exists, ensure that it's a directory
            if (error == ERROR_ALREADY_EXISTS) {
                const DWORD attributes = GetFileAttributesW(subpath.c_str());
                if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    return false;
                }
            } else {
                return false;
            }
        }
    }

    return true;
#else
    // if the path already exists, check whether it's a directory
    struct stat info;
    if (stat(path.c_str(), &info) == 0) {
        return S_ISDIR(info.st_mode);
    }

    size_t pos_slash = 1; // skip leading slashes for directory creation

    // process path from front to back, procedurally creating directories
    while ((pos_slash = path.find('/', pos_slash)) != std::string::npos) {
        const std::string subpath = path.substr(0, pos_slash);
        struct stat info;

        // if the path already exists, ensure that it's a directory
        if (stat(subpath.c_str(), &info) == 0) {
            if (!S_ISDIR(info.st_mode)) {
                return false;
            }
        } else {
            // create parent directories
            const int ret = mkdir(subpath.c_str(), 0755);
            if (ret != 0) {
                return false;
            }
        }

        pos_slash += 1;
    }

    return true;
#endif // _WIN32
}

// NOTE: this is copied from common.cpp to avoid linking with libcommon
static std::string fs_get_cache_directory() {
    std::string cache_directory = "";
    auto ensure_trailing_slash = [](std::string p) {
        // Make sure to add trailing slash
        if (p.back() != DIRECTORY_SEPARATOR) {
            p += DIRECTORY_SEPARATOR;
        }
        return p;
    };
    if (getenv("LLAMA_CACHE")) {
        cache_directory = std::getenv("LLAMA_CACHE");
    } else {
#if defined(__linux__) || defined(__FreeBSD__) || defined(_AIX) || \
    defined(__OpenBSD__) || defined(__NetBSD__)
        if (std::getenv("XDG_CACHE_HOME")) {
            cache_directory = std::getenv("XDG_CACHE_HOME");
        } else if (std::getenv("HOME")) {
            cache_directory = std::getenv("HOME") + std::string("/.cache/");
        } else {
#if defined(__linux__)
            /* no $HOME is defined, fallback to getpwuid */
            struct passwd *pw = getpwuid(getuid());
            if ((!pw) || (!pw->pw_dir)) {
                throw std::runtime_error("Failed to find $HOME directory");
            }

            cache_directory = std::string(pw->pw_dir) + std::string("/.cache/");
#else /* defined(__linux__) */
            throw std::runtime_error("Failed to find $HOME directory");
#endif /* defined(__linux__) */
        }
#elif defined(__APPLE__)
        cache_directory = std::getenv("HOME") + std::string("/Library/Caches/");
#elif defined(_WIN32)
        cache_directory = std::getenv("LOCALAPPDATA");
#elif defined(__EMSCRIPTEN__)
        GGML_ABORT("not implemented on this platform");
#else
#  error Unknown architecture
#endif
        cache_directory = ensure_trailing_slash(cache_directory);
        cache_directory += "llama.cpp";
    }
    return ensure_trailing_slash(cache_directory);
}

struct rpc_server_params {
    std::string              host        = "127.0.0.1";
    int                      port        = 50052;
    bool                     use_cache   = false;
    int                      n_threads   = std::max(1U, std::thread::hardware_concurrency()/2);
    std::vector<std::string> devices;
#if defined(__linux__)
    std::string              policy_file;  // Path to policy configuration file
    rpc_policy               policy;       // Peer credential policy
    bool        use_sandbox  = false;
#endif
};

static void print_usage(char ** argv, rpc_server_params params) {
    fprintf(stderr, "Usage: %s [options]\n\n", argv[0]);
    fprintf(stderr, "options:\n");
    fprintf(stderr, "  -h, --help                       show this help message and exit\n");
    fprintf(stderr, "  -t, --threads N                  number of threads for the CPU device (default: %d)\n", params.n_threads);
    fprintf(stderr, "  -d, --device <dev1,dev2,...>     comma-separated list of devices\n");
    fprintf(stderr, "  -H, --host HOST                  host to bind to, or path to unix socket ending in .sock (default: %s)\n", params.host.c_str());
    fprintf(stderr, "  -p, --port PORT                  port to bind to (default: %d)\n", params.port);
    fprintf(stderr, "  -c, --cache                      enable local file cache\n");
#if defined(__linux__)
    fprintf(stderr, "  -s, --sandbox                    enable basic Linux sandbox\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Unix socket policy options (apply to .sock endpoints)\n");
    fprintf(stderr, "  --policy-file FILE               load policy from configuration file\n");
    fprintf(stderr, "  --allowed-uid UID                allow connections from UID (can be repeated)\n");
    fprintf(stderr, "  --allowed-gid GID                allow connections from GID (can be repeated)\n");
    fprintf(stderr, "  --allowed-exe PATH               allow connections from executable (can be repeated)\n");
    fprintf(stderr, "  --no-allow-root                  do not automatically allow root (UID 0)\n");
    fprintf(stderr, "  --quiet-policy                   disable policy connection logging\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Security Policy file format (one directive per line):\n");
    fprintf(stderr, "  # Comment lines start with #\n");
    fprintf(stderr, "  host = 127.0.0.1\n");
    fprintf(stderr, "  port = 50052\n");
    fprintf(stderr, "  threads = 4\n");
    fprintf(stderr, "  device = CUDA0,CUDA1\n");
    fprintf(stderr, "  cache = true\n");
    fprintf(stderr, "  sandbox = true\n");
    fprintf(stderr, "  allowed_uid = 1000\n");
    fprintf(stderr, "  allowed_gid = 1000\n");
    fprintf(stderr, "  allowed_exe = /usr/bin/llama-cli\n");
    fprintf(stderr, "  allow_root = false\n");
    fprintf(stderr, "  log_connections = true\n");
#endif
    fprintf(stderr, "\n");
}

static bool rpc_server_params_parse(int argc, char ** argv, rpc_server_params & params) {
    std::string arg;
    for (int i = 1; i < argc; i++) {
        arg = argv[i];
        if (arg == "-H" || arg == "--host") {
            if (++i >= argc) {
                return false;
            }
            params.host = argv[i];
        } else if (arg == "-t" || arg == "--threads") {
            if (++i >= argc) {
                return false;
            }
            params.n_threads = std::stoi(argv[i]);
            if (params.n_threads <= 0) {
                fprintf(stderr, "error: invalid number of threads: %d\n", params.n_threads);
                return false;
            }
        } else if (arg == "-d" || arg == "--device") {
            if (++i >= argc) {
                return false;
            }
            const std::regex regex{ R"([,/]+)" };
            std::string dev_str = argv[i];
            std::sregex_token_iterator iter(dev_str.begin(), dev_str.end(), regex, -1);
            std::sregex_token_iterator end;
            for ( ; iter != end; ++iter) {
                try {
                    params.devices.push_back(*iter);
                } catch (const std::exception & ) {
                    fprintf(stderr, "error: invalid device: %s\n", iter->str().c_str());
                    return false;
                }
            }
        } else if (arg == "-p" || arg == "--port") {
            if (++i >= argc) {
                return false;
            }
            params.port = std::stoi(argv[i]);
            if (params.port <= 0 || params.port > 65535) {
                return false;
            }
        } else if (arg == "-c" || arg == "--cache") {
            params.use_cache = true;
#if defined(__linux__)
        } else if (arg == "-s" || arg == "--seccomp") {
            params.use_sandbox = true;
        } else if (arg == "--policy-file") {
            if (++i >= argc) {
                return false;
            }
            params.policy_file = argv[i];
        } else if (arg == "--allowed-uid") {
            if (++i >= argc) {
                return false;
            }
            try {
                params.policy.allowed_uids.insert(std::stoll(argv[i]));
            } catch (const std::exception &) {
                fprintf(stderr, "error: invalid UID: %s\n", argv[i]);
                return false;
            }
        } else if (arg == "--allowed-gid") {
            if (++i >= argc) {
                return false;
            }
            try {
                params.policy.allowed_gids.insert(std::stoll(argv[i]));
            } catch (const std::exception &) {
                fprintf(stderr, "error: invalid GID: %s\n", argv[i]);
                return false;
            }
        } else if (arg == "--allowed-exe") {
            if (++i >= argc) {
                return false;
            }
            params.policy.allowed_exes.insert(argv[i]);
        } else if (arg == "--no-allow-root") {
            params.policy.allow_root = false;
        } else if (arg == "--quiet-policy") {
            params.policy.log_connections = false;
#endif
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv, params);
            exit(0);
        } else {
            fprintf(stderr, "error: unknown argument: %s\n", arg.c_str());
            print_usage(argv, params);
            exit(0);
        }
    }
    return true;
}

#if defined(__linux__)

static bool apply_policy_directive(const std::string & key, const std::string & value,
                                   rpc_policy & policy, rpc_server_params & params) {
    // Server parameters
    if (key == "host") {
        params.host = value;
    } else if (key == "port") {
        try {
            params.port = std::stoi(value);
        } catch (...) {
            fprintf(stderr, "policy: invalid port: %s\n", value.c_str());
            return false;
        }
    } else if (key == "threads") {
        try {
            params.n_threads = std::stoi(value);
        } catch (...) {
            fprintf(stderr, "policy: invalid threads: %s\n", value.c_str());
            return false;
        }
    } else if (key == "device") {
        const std::regex regex{ R"([,/]+)" };
        std::sregex_token_iterator iter(value.begin(), value.end(), regex, -1);
        std::sregex_token_iterator end;
        for (; iter != end; ++iter) {
            params.devices.push_back(*iter);
        }
    } else if (key == "cache") {
        params.use_cache = (value == "true" || value == "1" || value == "yes");
    } else if (key == "sandbox") {
        params.use_sandbox = (value == "true" || value == "1" || value == "yes");
    }
    // Policy parameters
    else if (key == "allowed_uid") {
        try {
            policy.allowed_uids.insert(std::stoll(value));
        } catch (...) {
            fprintf(stderr, "policy: invalid allowed_uid: %s\n", value.c_str());
            return false;
        }
    } else if (key == "allowed_gid") {
        try {
            policy.allowed_gids.insert(std::stoll(value));
        } catch (...) {
            fprintf(stderr, "policy: invalid allowed_gid: %s\n", value.c_str());
            return false;
        }
    } else if (key == "allowed_exe") {
        policy.allowed_exes.insert(value);
    } else if (key == "allow_root") {
        policy.allow_root = (value == "true" || value == "1" || value == "yes");
    } else if (key == "log_connections") {
        policy.log_connections = (value == "true" || value == "1" || value == "yes");
    } else {
        fprintf(stderr, "policy: unknown directive: %s\n", key.c_str());
        return false;
    }
    return true;
}

static bool parse_policy_file(const std::string & path, rpc_policy & policy, rpc_server_params & params) {
    std::ifstream file(path);
    if (!file.is_open()) {
        fprintf(stderr, "Failed to open policy file: %s\n", path.c_str());
        return false;
    }

    std::string line;
    int line_num = 0;
    while (std::getline(file, line)) {
        line_num++;
        line = trim(line);

        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }

        // Parse key = value
        size_t eq_pos = line.find('=');
        if (eq_pos == std::string::npos) {
            fprintf(stderr, "policy:%d: missing '=' in directive: %s\n", line_num, line.c_str());
            return false;
        }

        std::string key = trim(line.substr(0, eq_pos));
        std::string value = trim(line.substr(eq_pos + 1));

        if (!apply_policy_directive(key, value, policy, params)) {
            fprintf(stderr, "policy:%d: failed to apply directive\n", line_num);
            return false;
        }
    }

    fprintf(stdout, "Loaded policy from %s\n", path.c_str());
    return true;
}
#endif  // __linux__

static std::vector<ggml_backend_dev_t> get_devices(const rpc_server_params & params) {
    std::vector<ggml_backend_dev_t> devices;
    if (!params.devices.empty()) {
        for (auto device : params.devices) {
            ggml_backend_dev_t dev = ggml_backend_dev_by_name(device.c_str());
            if (dev) {
                devices.push_back(dev);
            } else {
                fprintf(stderr, "error: unknown device: %s\n", device.c_str());
                fprintf(stderr, "available devices:\n");
                for (size_t i = 0; i < ggml_backend_dev_count(); i++) {
                    auto * dev = ggml_backend_dev_get(i);
                    size_t free, total;
                    ggml_backend_dev_memory(dev, &free, &total);
                    printf("  %s: %s (%zu MiB, %zu MiB free)\n", ggml_backend_dev_name(dev), ggml_backend_dev_description(dev), total / 1024 / 1024, free / 1024 / 1024);
                }
                return {};
            }
        }
    }

    // Try non-CPU devices first
    if (devices.empty()) {
        for (size_t i = 0; i < ggml_backend_dev_count(); i++) {
            ggml_backend_dev_t dev = ggml_backend_dev_get(i);
            if (ggml_backend_dev_type(dev) != GGML_BACKEND_DEVICE_TYPE_CPU) {
                devices.push_back(dev);
            }
        }
    }

    // If there are no accelerators, fallback to CPU device
    if (devices.empty()) {
        ggml_backend_dev_t dev = ggml_backend_dev_by_type(GGML_BACKEND_DEVICE_TYPE_CPU);
        if (dev) {
            devices.push_back(dev);
        }
    }

    return devices;
}

int main(int argc, char * argv[]) {
    rpc_server_params params;
    if (!rpc_server_params_parse(argc, argv, params)) {
        fprintf(stderr, "Invalid parameters\n");
        return 1;
    }

    ggml_backend_load_all();

#if defined(__linux__)
    // Load policy file if specified (command line args override policy file)
    if (!params.policy_file.empty()) {
        // Create a temporary params to load policy file defaults
        rpc_server_params policy_params;
        policy_params.policy = params.policy;  // Preserve CLI policy settings
        if (!parse_policy_file(params.policy_file, policy_params.policy, policy_params)) {
            return 1;
        }
        // CLI args take precedence, so we merge policy file into params
        // Only override if not set via CLI
        if (params.host == "127.0.0.1" && policy_params.host != "127.0.0.1") {
            params.host = policy_params.host;
        }
        if (params.port == 50052 && policy_params.port != 50052) {
            params.port = policy_params.port;
        }
        if (params.devices.empty() && !policy_params.devices.empty()) {
            params.devices = policy_params.devices;
        }
        if (!params.use_cache && policy_params.use_cache) {
            params.use_cache = policy_params.use_cache;
        }
#if defined(__linux__)
        if (!params.use_sandbox && policy_params.use_sandbox) {
            params.use_sandbox = policy_params.use_sandbox;
        }
#endif
        // Merge policy settings (CLI additions take precedence)
        for (auto uid : policy_params.policy.allowed_uids) {
            params.policy.allowed_uids.insert(uid);
        }
        for (auto gid : policy_params.policy.allowed_gids) {
            params.policy.allowed_gids.insert(gid);
        }
        for (const auto & exe : policy_params.policy.allowed_exes) {
            params.policy.allowed_exes.insert(exe);
        }
        // For boolean flags, CLI explicit settings override policy file
        // (handled by not overwriting if CLI set them)
    }
#endif

    bool is_unix_socket = params.host.size() >= 5 &&
                          params.host.rfind(".sock") == params.host.size() - 5;

    if (!is_unix_socket && params.host != "127.0.0.1") {
        fprintf(stderr, "\n");
        fprintf(stderr, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        fprintf(stderr, "WARNING: Host ('%s') is != '127.0.0.1'\n", params.host.c_str());
        fprintf(stderr, "         Never expose the RPC server to an open network!\n");
        fprintf(stderr, "         This is an experimental feature and is not secure!\n");
        fprintf(stderr, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        fprintf(stderr, "\n");
    }

#if defined(__linux__)
    // Print policy summary for Unix sockets
    if (is_unix_socket) {
        fprintf(stdout, "Unix socket policy:\n");
        fprintf(stdout, "  allow_root: %s\n", params.policy.allow_root ? "yes" : "no");
        if (!params.policy.allowed_uids.empty()) {
            fprintf(stdout, "  allowed_uids:");
            for (auto uid : params.policy.allowed_uids) {
                fprintf(stdout, " %lld", (long long)uid);
            }
            fprintf(stdout, "\n");
        }
        if (!params.policy.allowed_gids.empty()) {
            fprintf(stdout, "  allowed_gids:");
            for (auto gid : params.policy.allowed_gids) {
                fprintf(stdout, " %lld", (long long)gid);
            }
            fprintf(stdout, "\n");
        }
        if (!params.policy.allowed_exes.empty()) {
            fprintf(stdout, "  allowed_exes:\n");
            for (const auto & exe : params.policy.allowed_exes) {
                fprintf(stdout, "    %s\n", exe.c_str());
            }
        }
    }
#endif

    auto devices = get_devices(params);
    if (devices.empty()) {
        fprintf(stderr, "No devices found\n");
        return 1;
    }
    std::string endpoint;
    if (is_unix_socket) {
        endpoint = params.host;
    } else {
        endpoint = params.host + ":" + std::to_string(params.port);
    }
    const char * cache_dir = nullptr;
    std::string cache_dir_str;
    if (params.use_cache) {
        cache_dir_str = fs_get_cache_directory() + "rpc/";
        if (!fs_create_directory_with_parents(cache_dir_str)) {
            fprintf(stderr, "Failed to create cache directory: %s\n", cache_dir_str.c_str());
            return 1;
        }
        cache_dir = cache_dir_str.c_str();
    }

    ggml_backend_reg_t reg = ggml_backend_reg_by_name("RPC");
    if (!reg) {
        fprintf(stderr, "Failed to find RPC backend\n");
        return 1;
    }

    auto start_server_fn = (decltype(ggml_backend_rpc_start_server)*) ggml_backend_reg_get_proc_address(reg, "ggml_backend_rpc_start_server");
    if (!start_server_fn) {
        fprintf(stderr, "Failed to obtain RPC backend start server function\n");
        return 1;
    }

    const char * auth_token_s = std::getenv("GGML_RPC_AUTH_TOKEN");

    if (auth_token_s == nullptr) {
        fprintf(stderr, "[%s] Authentication token (GGML_RPC_AUTH_TOKEN) secret not set\n", __func__);
        return 0;
    }

#if defined(__linux__)
    // Create the client connection verification callback
    // Capture policy by value since it needs to outlive this scope
    rpc_policy policy = params.policy;
    ggml_rpc_on_client_connect_t on_client_connect = [policy](int sockfd, const ggml_rpc_peer_cred_t & cred) -> bool {
        (void)sockfd;  // Available for additional checks if needed
        return verify_peer_credentials(policy, cred);
    };

    if (params.use_sandbox) {
        bool use_cache = params.use_cache;
        start_server_fn(endpoint.c_str(), cache_dir, params.n_threads, devices.size(), devices.data(),
            [use_cache]() {
                install_chroot();
                install_rlimits(use_cache);
                install_no_new_privs();
                install_seccomp_filter();
            },
            on_client_connect);
    } else {
        start_server_fn(endpoint.c_str(), cache_dir, params.n_threads, devices.size(), devices.data(),
                        nullptr, on_client_connect);
    }
#else
    // Non-Linux and Windows
    start_server_fn(endpoint.c_str(), cache_dir, params.n_threads, devices.size(), devices.data(),
                    nullptr, nullptr);
#endif

    return 0;
}
