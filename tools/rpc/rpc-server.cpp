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
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <fcntl.h>

// Try to include libcap if available
#ifdef __has_include
#  if __has_include(<sys/capability.h>)
#    include <sys/capability.h>
#    define HAVE_LIBCAP 1
#  endif
#endif

// Capability constants (defined in <sys/capability.h> / <linux/capability.h>)
// Define fallbacks in case neither header is available
#ifndef CAP_SYS_ADMIN
#  include <linux/capability.h>
#endif
#ifndef CAP_SYS_ADMIN
#  define CAP_SYS_ADMIN    21
#  define CAP_IPC_LOCK     14
#  define CAP_SYS_RESOURCE 24
#endif

// Compatibility definitions
#ifndef CAP_LAST_CAP
#define CAP_LAST_CAP 40  // As of Linux 5.10+, but we'll try up to this
#endif

#endif

#if defined(__linux__)
#include <sys/types.h>
#include <pwd.h>
#endif

// Forward declaration (defined later in file, used by sandbox code)
static bool fs_create_directory_with_parents(const std::string & path);

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
// ============================================================================
// Enhanced Linux Sandbox Implementation
// ============================================================================
//
// Security layers (applied in order):
// 1. Cgroup v2 resource limits (memory, PIDs)
// 2. Namespace isolation (user, net, mount, UTS, IPC)
// 3. Filesystem isolation via pivot_root in mount namespace (stronger than chroot)
// 4. Process-level resource limits (rlimits for file descriptors, processes, file size)
// 5. Capability dropping (all caps dropped; GPU mode preserves SYS_ADMIN, IPC_LOCK, SYS_RESOURCE)
// 6. PR_SET_NO_NEW_PRIVS (prevents privilege escalation)
// 7. Seccomp-BPF filter with argument filtering (syscall whitelist, blocks dangerous operations)
//
// Key improvements over basic chroot + seccomp:
// - Namespace isolation prevents process visibility, network access, and mount escapes
// - pivot_root in mount namespace is more secure than chroot alone
// - Capability dropping ensures no elevated privileges even if running as root
// - Cgroup limits provide hierarchical resource control across process tree
// - Argument filtering in seccomp blocks PROT_EXEC in mmap/mprotect (prevents JIT/code injection)
// - User namespace enables unprivileged sandboxing without requiring root
// - GPU-aware mode: Automatically bind-mounts GPU devices and preserves GPU capabilities
//   when CUDA/GPU backend is detected (trades device isolation for GPU functionality)
//
// Limitations:
// - PID namespace requires fork to take effect, so main process still in host PID namespace
// - Cgroup setup requires writable /sys/fs/cgroup (may need root or cgroup delegation)
// - Some features require recent kernel (user namespace: 3.8+, seccomp arg filtering: 3.5+)
// - Cgroup v2 required for unified hierarchy (older systems use cgroup v1)
//
// Trade-offs:
// - PROT_EXEC blocking may break JIT compilers or programs that need executable memory
// - Network namespace isolation means no network access (appropriate for local RPC server)
// - Aggressive syscall filtering may break compatibility with some libraries
//
// ============================================================================

// Scan a range of numbered device paths and append any that exist to the list
static void scan_device_range(std::vector<std::string>& paths, const char* fmt, int start, int end) {
    for (int i = start; i < end; i++) {
        char dev_path[64];
        snprintf(dev_path, sizeof(dev_path), fmt, i);
        if (access(dev_path, F_OK) == 0) {
            paths.push_back(dev_path);
        }
    }
}

// Detect available GPU device nodes on the host system
static void detect_gpu_devices(std::vector<std::string>& gpu_device_paths) {
    // NVIDIA numbered devices (nvidia0-nvidia15)
    scan_device_range(gpu_device_paths, "/dev/nvidia%d", 0, 16);

    // NVIDIA control devices
    for (const char* dev : {"/dev/nvidiactl", "/dev/nvidia-modeset",
                             "/dev/nvidia-uvm", "/dev/nvidia-uvm-tools"}) {
        if (access(dev, F_OK) == 0) {
            gpu_device_paths.push_back(dev);
        }
    }

    // AMD/Intel DRI: card devices (card0-card15) and render nodes (renderD128-renderD143)
    scan_device_range(gpu_device_paths, "/dev/dri/card%d",    0,   16);
    scan_device_range(gpu_device_paths, "/dev/dri/renderD%d", 128, 144);

    if (!gpu_device_paths.empty()) {
        fprintf(stdout, "Detected %zu GPU device nodes:\n", gpu_device_paths.size());
        for (const auto& dev : gpu_device_paths) {
            fprintf(stdout, "  - %s\n", dev.c_str());
        }
    }
}

// Close unnecessary file descriptors to prevent fd leaks
// Preserves stdin(0), stdout(1), stderr(2), and low-numbered fds that might be server sockets
// Only closes fds >= min_fd_to_close to avoid accidentally closing critical server infrastructure
static void sanitize_file_descriptors(int min_fd_to_close) {
    // Default to a conservative threshold to avoid closing server sockets
    // which are typically opened early and have low fd numbers
    if (min_fd_to_close < 0) {
        min_fd_to_close = 10;  // Conservative: preserve fds 0-9
    }

    DIR *dir = opendir("/proc/self/fd");
    if (!dir) {
        fprintf(stderr, "Warning: Failed to open /proc/self/fd for fd sanitization: %s\n", strerror(errno));
        // Fallback: try to close fds in a reasonable range
        for (int fd = min_fd_to_close; fd < 1024; fd++) {
            close(fd);  // Will silently fail for invalid fds, which is fine
        }
        return;
    }

    int dir_fd = dirfd(dir);
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;

        int fd = atoi(entry->d_name);
        // Only close fds above the threshold, and not the dir fd itself
        if (fd >= min_fd_to_close && fd != dir_fd) {
            close(fd);
        }
    }
    closedir(dir);

    fprintf(stdout, "File descriptors >= %d sanitized\n", min_fd_to_close);
}

// Drop all Linux capabilities except those required for GPU access
static void drop_capabilities_gpu_aware(bool preserve_gpu_caps) {
    // Capabilities to preserve for GPU operations
    const int gpu_required_caps[] = {
        CAP_SYS_ADMIN,    // Device access, GPU ioctls, some memory operations
        CAP_IPC_LOCK,     // Pin memory for DMA transfers (cudaMallocHost, etc.)
        CAP_SYS_RESOURCE, // Override memory limits for large GPU allocations
        -1
    };

    auto is_gpu_cap = [&](int cap) {
        for (const int* p = gpu_required_caps; *p != -1; p++) {
            if (*p == cap) return true;
        }
        return false;
    };

    // Clear capability bounding set (except GPU-required if requested)
    for (int cap = 0; cap <= CAP_LAST_CAP; cap++) {
        if (preserve_gpu_caps && is_gpu_cap(cap)) {
            continue;  // Skip GPU-required capabilities
        }

        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0) {
            // Capability might not exist, continue
            if (errno != EINVAL) {
                fprintf(stderr, "Warning: Failed to drop capability %d: %s\n", cap, strerror(errno));
            }
        }
    }

    // Clear ambient capabilities (except GPU-required if requested)
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif
    if (!preserve_gpu_caps) {
        // Clear all ambient capabilities
        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0) {
            if (errno != EINVAL) {
                fprintf(stderr, "Warning: Failed to clear ambient capabilities: %s\n", strerror(errno));
            }
        }
    }

    // If libcap is available, use it for more granular control
#ifdef HAVE_LIBCAP
    if (preserve_gpu_caps) {
        // Create capability set with only GPU-required caps
        cap_t cap_set = cap_init();
        if (cap_set) {
            cap_value_t caps_array[3] = {CAP_SYS_ADMIN, CAP_IPC_LOCK, CAP_SYS_RESOURCE};
            if (cap_set_flag(cap_set, CAP_EFFECTIVE, 3, caps_array, CAP_SET) == 0 &&
                cap_set_flag(cap_set, CAP_PERMITTED, 3, caps_array, CAP_SET) == 0) {
                if (cap_set_proc(cap_set) < 0) {
                    fprintf(stderr, "Warning: Failed to set GPU capabilities: %s\n", strerror(errno));
                }
            }
            cap_free(cap_set);
        }
    } else {
        // Drop all capabilities
        cap_t empty = cap_init();
        if (empty) {
            if (cap_set_proc(empty) < 0) {
                fprintf(stderr, "Warning: Failed to drop capabilities via cap_set_proc: %s\n", strerror(errno));
            }
            cap_free(empty);
        } else {
            fprintf(stderr, "Warning: Failed to initialize capability state\n");
        }
    }
#else
    fprintf(stdout, "Note: libcap not available, using prctl-only capability dropping\n");
#endif

    if (preserve_gpu_caps) {
        fprintf(stdout, "GPU-aware capabilities: preserved CAP_SYS_ADMIN, CAP_IPC_LOCK, CAP_SYS_RESOURCE\n");
    } else {
        fprintf(stdout, "All capabilities dropped (CPU-only mode)\n");
    }
}

// Write a string value to a cgroup control file
static bool write_cgroup_file(const char * path, const char * value, const char * label) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "Warning: Failed to open %s: %s\n", path, strerror(errno));
        return false;
    }
    bool ok = write(fd, value, strlen(value)) > 0;
    close(fd);
    if (ok) {
        fprintf(stdout, "%s\n", label);
    } else {
        fprintf(stderr, "Warning: Failed to write %s: %s\n", path, strerror(errno));
    }
    return ok;
}

// Setup cgroup v2 resource limits (optional, requires cgroup v2)
static void setup_cgroup_limits() {
    const char * cgroup_base = "/sys/fs/cgroup";
    const char * cgroup_name = "ggml-rpc-sandbox";

    // Check if cgroup v2 is available
    struct stat st;
    if (stat(cgroup_base, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stdout, "Cgroup v2 not available, skipping cgroup limits\n");
        return;
    }

    // Try to create our cgroup
    char cgroup_path[512];
    snprintf(cgroup_path, sizeof(cgroup_path), "%s/%s", cgroup_base, cgroup_name);

    if (mkdir(cgroup_path, 0755) < 0 && errno != EEXIST) {
        fprintf(stderr, "Warning: Failed to create cgroup: %s\n", strerror(errno));
        return;
    }

    char path[512];

    // Memory limit: 4GB — adjust for your model size
    snprintf(path, sizeof(path), "%s/memory.max", cgroup_path);
    write_cgroup_file(path, "4294967296\n", "Cgroup memory limit set to 4GB");

    // PIDs limit: prevents fork bombs (mainly limits thread creation since fork is blocked)
    snprintf(path, sizeof(path), "%s/pids.max", cgroup_path);
    write_cgroup_file(path, "128\n", "Cgroup PIDs limit set to 128");

    // Move current process into the cgroup
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
    snprintf(path, sizeof(path), "%s/cgroup.procs", cgroup_path);
    write_cgroup_file(path, pid_str, "Process moved to cgroup");
}

// Setup namespace isolation
static bool setup_namespaces() {
    // Create new namespaces
    // CLONE_NEWUSER must be first to enable unprivileged operation
    // We'll do this in multiple steps for compatibility

    // First, unshare user namespace if not root (for unprivileged sandboxing)
    bool is_root = (geteuid() == 0);

    if (!is_root) {
        if (unshare(CLONE_NEWUSER) < 0) {
            fprintf(stderr, "Warning: Failed to create user namespace: %s\n", strerror(errno));
            fprintf(stderr, "Note: Continuing without user namespace (requires root for other namespaces)\n");
            return false;
        }
        fprintf(stdout, "User namespace created\n");

        // Map current user to root in the new namespace
        int uid = getuid();
        int gid = getgid();

        // Write uid_map
        char uid_map[128];
        snprintf(uid_map, sizeof(uid_map), "0 %d 1\n", uid);
        int fd = open("/proc/self/uid_map", O_WRONLY);
        if (fd >= 0) {
            write(fd, uid_map, strlen(uid_map));
            close(fd);
        }

        // Deny setgroups
        fd = open("/proc/self/setgroups", O_WRONLY);
        if (fd >= 0) {
            write(fd, "deny\n", 5);
            close(fd);
        }

        // Write gid_map
        char gid_map[128];
        snprintf(gid_map, sizeof(gid_map), "0 %d 1\n", gid);
        fd = open("/proc/self/gid_map", O_WRONLY);
        if (fd >= 0) {
            write(fd, gid_map, strlen(gid_map));
            close(fd);
        }
    }

    // Create other namespaces (excluding CLONE_NEWNS — handled by setup_mount_namespace)
    // Note: CLONE_NEWPID requires fork to take effect, so we omit it here
    int unshare_flags = CLONE_NEWNET | CLONE_NEWUTS | CLONE_NEWIPC;

    if (unshare(unshare_flags) < 0) {
        fprintf(stderr, "Warning: Failed to create namespaces: %s\n", strerror(errno));
        return false;
    }

    fprintf(stdout, "Network, UTS, and IPC namespaces created\n");

    // Note: PID namespace requires fork, which we can't easily do here
    // without restructuring the entire application. The parent process
    // will still be in the original PID namespace, but child processes would be isolated.

    return true;
}

// Setup mount namespace with pivot_root (more secure than chroot)
static bool setup_mount_namespace(const char * jail_path, const std::vector<std::string>* gpu_devices) {
    // Ensure we're in a mount namespace
    if (unshare(CLONE_NEWNS) < 0) {
        fprintf(stderr, "Warning: Failed to create mount namespace: %s\n", strerror(errno));
        return false;
    }

    // Make everything private to prevent mount propagation
    if (mount(nullptr, "/", nullptr, MS_PRIVATE | MS_REC, nullptr) < 0) {
        fprintf(stderr, "Warning: Failed to make mounts private: %s\n", strerror(errno));
    }

    // Create jail directory if it doesn't exist
    if (mkdir(jail_path, 0755) < 0 && errno != EEXIST) {
        fprintf(stderr, "Warning: Failed to create jail directory: %s\n", strerror(errno));
        return false;
    }

    // Create necessary subdirectories
    char dev_path[256], proc_path[256], tmp_path[256];
    snprintf(dev_path, sizeof(dev_path), "%s/dev", jail_path);
    snprintf(proc_path, sizeof(proc_path), "%s/proc", jail_path);
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp", jail_path);

    mkdir(dev_path, 0755);
    mkdir(proc_path, 0555);
    mkdir(tmp_path, 0777);

    // Mount tmpfs for writable areas with size limits
    if (mount("tmpfs", tmp_path, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=16M") < 0) {
        fprintf(stderr, "Warning: Failed to mount tmpfs on /tmp: %s\n", strerror(errno));
    }

    // Mount minimal /dev with necessary devices
    if (mount("tmpfs", dev_path, "tmpfs", MS_NOSUID | MS_NOEXEC, "size=1M") < 0) {
        fprintf(stderr, "Warning: Failed to mount tmpfs on /dev: %s\n", strerror(errno));
    } else {
        // Create essential device nodes
        char null_path[256], zero_path[256], urandom_path[256];
        snprintf(null_path, sizeof(null_path), "%s/null", dev_path);
        snprintf(zero_path, sizeof(zero_path), "%s/zero", dev_path);
        snprintf(urandom_path, sizeof(urandom_path), "%s/urandom", dev_path);

        // These will fail if we don't have permissions, but that's okay
        mknod(null_path, S_IFCHR | 0666, makedev(1, 3));
        mknod(zero_path, S_IFCHR | 0666, makedev(1, 5));
        mknod(urandom_path, S_IFCHR | 0444, makedev(1, 9));
    }

    // Bind-mount GPU device nodes if requested
    if (gpu_devices != nullptr && !gpu_devices->empty()) {
        fprintf(stdout, "Bind-mounting GPU devices into jail...\n");

        for (const auto& host_dev_path : *gpu_devices) {
            char jail_dev_path[512];
            snprintf(jail_dev_path, sizeof(jail_dev_path), "%s%s", jail_path, host_dev_path.c_str());

            // Create parent directories (/dev/dri for DRI devices)
            fs_create_directory_with_parents(jail_dev_path);

            // Get device major/minor numbers from host
            struct stat st;
            if (stat(host_dev_path.c_str(), &st) < 0) {
                fprintf(stderr, "Warning: Failed to stat %s: %s\n", host_dev_path.c_str(), strerror(errno));
                continue;
            }

            // Create device node placeholder in jail
            if (mknod(jail_dev_path, S_IFCHR | 0666, st.st_rdev) < 0 && errno != EEXIST) {
                fprintf(stderr, "Warning: Failed to create device node %s: %s\n", jail_dev_path, strerror(errno));
                // Try bind-mounting anyway
            }

            // Bind mount from host to jail
            if (mount(host_dev_path.c_str(), jail_dev_path, NULL, MS_BIND, NULL) < 0) {
                fprintf(stderr, "Warning: Failed to bind-mount %s: %s\n", host_dev_path.c_str(), strerror(errno));
            } else {
                fprintf(stdout, "  ✓ Bind-mounted: %s\n", host_dev_path.c_str());
            }
        }
    }

    // Use pivot_root instead of chroot for stronger isolation
    // First, mount the jail as a bind mount to itself (requirement for pivot_root)
    if (mount(jail_path, jail_path, nullptr, MS_BIND | MS_REC, nullptr) < 0) {
        fprintf(stderr, "Warning: Failed to bind mount jail: %s\n", strerror(errno));
        return false;
    }

    // Create old_root directory inside new root
    char old_root_path[256];
    snprintf(old_root_path, sizeof(old_root_path), "%s/.old_root", jail_path);
    if (mkdir(old_root_path, 0000) < 0 && errno != EEXIST) {
        fprintf(stderr, "Warning: Failed to create old_root: %s\n", strerror(errno));
    }

    // Change to the new root
    if (chdir(jail_path) < 0) {
        fprintf(stderr, "Warning: Failed to chdir to jail: %s\n", strerror(errno));
        return false;
    }

    // Perform pivot_root
    if (syscall(SYS_pivot_root, ".", ".old_root") < 0) {
        fprintf(stderr, "Warning: pivot_root failed, falling back to chroot: %s\n", strerror(errno));
        // Fallback to chroot - use "." since we already chdir'd into jail_path
        if (chroot(".") < 0) {
            fprintf(stderr, "Warning: chroot also failed: %s\n", strerror(errno));
            return false;
        }
    } else {
        // Unmount and remove old root
        if (umount2(".old_root", MNT_DETACH) < 0) {
            fprintf(stderr, "Warning: Failed to unmount old root: %s\n", strerror(errno));
        }
        rmdir(".old_root");
        fprintf(stdout, "pivot_root successful\n");
    }

    // Change to root directory
    if (chdir("/") < 0) {
        fprintf(stderr, "Warning: Failed to chdir to /: %s\n", strerror(errno));
        return false;
    }

    // Mount new proc filesystem (read-only)
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RDONLY, nullptr) < 0) {
        fprintf(stderr, "Warning: Failed to mount proc: %s\n", strerror(errno));
    }

    fprintf(stdout, "Mount namespace setup complete\n");
    return true;
}

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

// Filesystem isolation entry point: tries pivot_root in a mount namespace first,
// falls back to plain chroot if that fails (e.g. insufficient privileges)
static void install_chroot(const std::vector<std::string>* gpu_devices) {
    const char * jail_path = "/tmp/secure-ggml-rpc-jail";

    // Try the more secure mount namespace approach first
    if (setup_mount_namespace(jail_path, gpu_devices)) {
        fprintf(stdout, "Secure mount namespace jail installed at %s\n", jail_path);
        return;
    }

    // Fallback to traditional chroot if mount namespace setup failed
    fprintf(stdout, "Falling back to basic chroot isolation\n");

    if (geteuid() != 0) {
        fprintf(stdout, "Skipping chroot (requires root privileges)\n");
        return;
    }

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

    fprintf(stdout, "Basic chroot jail installed at %s\n", jail_path);
}

static void install_no_new_privs() {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        fprintf(stderr, "Warning: Failed to set PR_SET_NO_NEW_PRIVS: %s\n", strerror(errno));
        return;
    }

    fprintf(stdout, "PR_SET_NO_NEW_PRIVS installed\n");
}

static void install_seccomp_filter() {
    // Use SCMP_ACT_ERRNO for more graceful degradation instead of immediately killing the process
    // This allows better debugging and more controlled failures
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    if (!ctx) {
        fprintf(stderr, "Failed to create seccomp filter %s\n", strerror(errno));
        exit(1);
    }

    // Allow essential syscalls for the RPC server operation
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlinkat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);

    // Allow mmap but restrict executable pages
    // Block PROT_EXEC to prevent JIT/code generation attacks
    {
        struct scmp_arg_cmp mmap_prot_arg = {2, SCMP_CMP_MASKED_EQ, PROT_EXEC, 0};
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 1, mmap_prot_arg);
    }

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept4), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpeername), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sysinfo), 0);

    // Allow mprotect but block adding PROT_EXEC
    {
        struct scmp_arg_cmp mprotect_prot_arg = {2, SCMP_CMP_MASKED_EQ, PROT_EXEC, 0};
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 1, mprotect_prot_arg);
    }

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

    // Explicitly block dangerous syscalls with SCMP_ACT_KILL for critical violations
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ptrace), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(fork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(vfork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clone), 0);

    if (seccomp_load(ctx) < 0) {
        fprintf(stderr, "Failed to load seccomp filter %s\n", strerror(errno));
        exit(1);
    } else {
        fprintf(stdout, "Seccomp filter installed (ERRNO mode with argument filtering)\n");
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
    int         socket_mode  = 0660;       // Unix socket file permissions (octal)
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
    fprintf(stderr, "  -s, --sandbox                    enable enhanced Linux sandbox\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Sandbox behavior with GPU devices:\n");
    fprintf(stderr, "  When GPU devices are detected, the sandbox automatically:\n");
    fprintf(stderr, "    • Bind-mounts GPU device nodes (/dev/nvidia*, /dev/dri/*) into jail\n");
    fprintf(stderr, "    • Preserves capabilities: CAP_SYS_ADMIN, CAP_IPC_LOCK, CAP_SYS_RESOURCE\n");
    fprintf(stderr, "    • All other protections remain active (namespaces, seccomp, cgroups)\n");
    fprintf(stderr, "  For CPU-only workloads: Full device isolation is used\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Unix socket policy options (apply to .sock endpoints)\n");
    fprintf(stderr, "  --policy-file FILE               load policy from configuration file\n");
    fprintf(stderr, "  --allowed-uid UID                allow connections from UID (can be repeated)\n");
    fprintf(stderr, "  --allowed-gid GID                allow connections from GID (can be repeated)\n");
    fprintf(stderr, "  --allowed-exe PATH               allow connections from executable (can be repeated)\n");
    fprintf(stderr, "  --no-allow-root                  do not automatically allow root (UID 0)\n");
    fprintf(stderr, "  --quiet-policy                   disable policy connection logging\n");
    fprintf(stderr, "  --socket-mode MODE               unix socket permissions in octal (default: 660)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Security Policy file format (one directive per line):\n");
    fprintf(stderr, "  # Comment lines start with #\n");
    fprintf(stderr, "  host = 127.0.0.1\n");
    fprintf(stderr, "  port = 50052\n");
    fprintf(stderr, "  threads = 4\n");
    fprintf(stderr, "  device = CUDA0,CUDA1\n");
    fprintf(stderr, "  cache = true\n");
    fprintf(stderr, "  sandbox = true\n");
    fprintf(stderr, "  socket_mode = 660\n");
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
        } else if (arg == "-s" || arg == "--sandbox") {
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
        } else if (arg == "--socket-mode") {
            if (++i >= argc) {
                return false;
            }
            try {
                params.socket_mode = std::stoi(argv[i], nullptr, 8);
            } catch (const std::exception &) {
                fprintf(stderr, "error: invalid socket mode (expected octal, e.g. 660): %s\n", argv[i]);
                return false;
            }
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
    } else if (key == "socket_mode") {
        try {
            params.socket_mode = std::stoi(value, nullptr, 8);
        } catch (...) {
            fprintf(stderr, "policy: invalid socket_mode (expected octal, e.g. 660): %s\n", value.c_str());
            return false;
        }
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
        int default_threads = std::max(1U, std::thread::hardware_concurrency()/2);
        if (params.host == "127.0.0.1" && policy_params.host != "127.0.0.1") {
            params.host = policy_params.host;
        }
        if (params.port == 50052 && policy_params.port != 50052) {
            params.port = policy_params.port;
        }
        if (params.n_threads == default_threads && policy_params.n_threads != default_threads) {
            params.n_threads = policy_params.n_threads;
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
        if (params.socket_mode == 0660 && policy_params.socket_mode != 0660) {
            params.socket_mode = policy_params.socket_mode;
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

        // Detect GPU devices on the host BEFORE entering sandbox
        std::vector<std::string> gpu_devices;
        bool has_gpu = false;
        for (const auto& dev : devices) {
            if (ggml_backend_dev_type(dev) != GGML_BACKEND_DEVICE_TYPE_CPU) {
                has_gpu = true;
                break;
            }
        }

        if (has_gpu) {
            detect_gpu_devices(gpu_devices);
        }

        // Capture socket info for chmod inside callback (ggml-rpc hardcodes chmod 0770 after bind)
        std::string sock_path = is_unix_socket ? params.host : "";
        int sock_mode = params.socket_mode;

        start_server_fn(endpoint.c_str(), cache_dir, params.n_threads, devices.size(), devices.data(),
            [use_cache, has_gpu, gpu_devices, sock_path, sock_mode]() {
                // Fix socket permissions immediately — ggml-rpc hardcodes 0770 after bind(),
                // so we must override it here, before pivot_root makes the path inaccessible.
                if (!sock_path.empty()) {
                    if (chmod(sock_path.c_str(), sock_mode) < 0) {
                        fprintf(stderr, "Warning: Failed to set socket mode %03o on %s: %s\n",
                                sock_mode, sock_path.c_str(), strerror(errno));
                    } else {
                        fprintf(stdout, "Socket permissions set to %03o on %s\n", sock_mode, sock_path.c_str());
                    }
                }

                fprintf(stdout, "\n=== Initializing Enhanced Sandbox ===\n");

                if (has_gpu) {
                    fprintf(stdout, "GPU-aware mode: Device isolation weakened for GPU access\n");
                } else {
                    fprintf(stdout, "CPU-only mode: Full device isolation active\n");
                }

                // 1. Setup cgroup limits first (before namespace isolation)
                // This must be done before entering namespaces that might restrict access to /sys
                setup_cgroup_limits();

                // 2. Setup namespaces (for isolation)
                // This enables user namespace for unprivileged operation
                setup_namespaces();

                // 3. Sanitize file descriptors (optional, disabled by default for safety)
                // Uncomment if you want to close fds >= 100 to prevent leaks
                // This is conservative to avoid closing server sockets (typically fd 3-10)
                // sanitize_file_descriptors(100);

                // 4. Setup filesystem isolation with GPU device bind-mounts if needed
                install_chroot(has_gpu ? &gpu_devices : nullptr);

                // 5. Install resource limits (process-level via rlimits)
                install_rlimits(use_cache);

                // 6. Drop capabilities (preserve GPU-required if GPU present)
                drop_capabilities_gpu_aware(has_gpu);

                // 7. Install no_new_privs (must be before seccomp)
                install_no_new_privs();

                // 8. Install seccomp filter (MUST BE LAST)
                // Seccomp must be installed after all other prctl calls
                install_seccomp_filter();

                fprintf(stdout, "=== Sandbox Initialization Complete ===\n\n");
            },
            on_client_connect);
    } else {
        std::string sock_path = is_unix_socket ? params.host : "";
        int sock_mode = params.socket_mode;
        auto sock_create_cb = is_unix_socket
            ? std::function<void()>([sock_path, sock_mode]() {
                if (chmod(sock_path.c_str(), sock_mode) < 0) {
                    fprintf(stderr, "Warning: Failed to set socket mode %03o on %s: %s\n",
                            sock_mode, sock_path.c_str(), strerror(errno));
                } else {
                    fprintf(stdout, "Socket permissions set to %03o on %s\n", sock_mode, sock_path.c_str());
                }
              })
            : std::function<void()>(nullptr);
        start_server_fn(endpoint.c_str(), cache_dir, params.n_threads, devices.size(), devices.data(),
                        sock_create_cb, on_client_connect);
    }

#else
    // Non-Linux and Windows
    start_server_fn(endpoint.c_str(), cache_dir, params.n_threads, devices.size(), devices.data(),
                    nullptr, nullptr);
#endif

    return 0;
}
