#include <saga/worker.hpp>
#include "internal.hpp"
#ifndef SAGA_EXECUTOR_ONLY
#include "executor_image.hpp"
#endif

#include <arpa/inet.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/memfd.h>
#include <linux/openat2.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sqlite3.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif
#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 0x0008U
#endif

#ifndef LANDLOCK_ACCESS_FS_RESOLVE_UNIX
#define LANDLOCK_ACCESS_FS_RESOLVE_UNIX (1ULL << 16)
#endif
#ifndef LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
#define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0)
#define LANDLOCK_SCOPE_SIGNAL (1ULL << 1)
#endif

namespace saga {
int landlock_abi() noexcept {
    return static_cast<int>(syscall(SYS_landlock_create_ruleset, nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION));
}

namespace detail {
namespace {
constexpr std::size_t max_data = 4 * 1024 * 1024;
constexpr std::size_t max_content = 1024 * 1024;

// Fixed ABI9 layout also compiles with pre-ABI9 distribution headers.
struct RulesetAttributes {
    std::uint64_t handled_access_fs;
    std::uint64_t handled_access_net;
    std::uint64_t scoped;
};

struct Fd {
    int value = -1;
    explicit Fd(int descriptor = -1) : value(descriptor) {}
    ~Fd() { if (value >= 0) close(value); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
};

[[noreturn]] void fail_system(const char* operation) {
    throw std::runtime_error(std::string(operation) + ": " + std::strerror(errno));
}

std::string text(const Json& object, const char* field) {
    const auto value = object.at(field).get<std::string>();
    if (value.find('\0') != std::string::npos)
        throw std::runtime_error(std::string("NUL in ") + field);
    return value;
}

int open_regular(const std::string& path, int flags) {
    if (path.empty() || path[0] != '/' || path.find('\0') != std::string::npos)
        throw std::runtime_error("resource path must be absolute");
    std::size_t position = 1;
    while (position <= path.size()) {
        const auto end = path.find('/', position);
        const auto component = path.substr(position, end - position);
        if (component.empty() || component == "." || component == "..")
            throw std::runtime_error("resource path must be normalized");
        if (end == std::string::npos) break;
        position = end + 1;
    }
    open_how how{};
    how.flags = static_cast<__u64>(flags | O_CLOEXEC);
    how.resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
    const int descriptor = static_cast<int>(syscall(SYS_openat2, AT_FDCWD, path.c_str(), &how, sizeof(how)));
    if (descriptor < 0) fail_system("open resource without symlinks");
    struct stat attributes{};
    if (fstat(descriptor, &attributes) < 0 || !S_ISREG(attributes.st_mode)) {
        close(descriptor);
        throw std::runtime_error("resource must be a regular file");
    }
    return descriptor;
}

[[maybe_unused]] void install_landlock(const Json& sandbox) {
    if (landlock_abi() < 9) throw std::runtime_error("Landlock ABI >= 9 is required");
    RulesetAttributes attributes{};
    attributes.handled_access_fs = (1ULL << 17) - 1;
    attributes.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;
    attributes.scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL;
    const Fd ruleset(static_cast<int>(syscall(SYS_landlock_create_ruleset, &attributes, sizeof(attributes), 0)));
    if (ruleset.value < 0) fail_system("create Landlock ruleset");
    if (!sandbox.at("paths").is_array() || !sandbox.at("tcp_ports").is_array())
        throw std::runtime_error("invalid sandbox grants");
    for (const auto& item : sandbox.at("paths")) {
        const auto path = text(item, "path");
        const auto access = text(item, "access");
        const Fd target(open_regular(path, O_PATH));
        landlock_path_beneath_attr rule{};
        if (access == "read") rule.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
        else if (access == "write") rule.allowed_access = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE;
        else throw std::runtime_error("unknown sandbox file access");
        rule.parent_fd = target.value;
        if (syscall(SYS_landlock_add_rule, ruleset.value, LANDLOCK_RULE_PATH_BENEATH, &rule, 0) < 0)
            fail_system("add Landlock file rule");
    }
    for (const auto& value : sandbox.at("tcp_ports")) {
        if (!value.is_number_integer()) throw std::runtime_error("TCP grant must be an integer");
        const auto port = value.get<std::int64_t>();
        if (port <= 0 || port > 65535) throw std::runtime_error("TCP grant out of range");
        landlock_net_port_attr rule{};
        rule.allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP;
        rule.port = static_cast<__u64>(port);
        if (syscall(SYS_landlock_add_rule, ruleset.value, LANDLOCK_RULE_NET_PORT, &rule, 0) < 0)
            fail_system("add Landlock TCP rule");
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) fail_system("set no_new_privs");
    if (syscall(SYS_landlock_restrict_self, ruleset.value, 0) < 0)
        fail_system("restrict process with Landlock");
}

[[maybe_unused]] void install_seccomp() {
#if defined(__x86_64__)
    constexpr unsigned int architecture = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
    constexpr unsigned int architecture = AUDIT_ARCH_AARCH64;
#else
    throw std::runtime_error("unsupported seccomp architecture");
#endif
    std::vector<sock_filter> code;
    auto statement = [&](unsigned short opcode, unsigned int value) {
        code.push_back(BPF_STMT(opcode, value));
    };
    auto jump = [&](unsigned short opcode, unsigned int value, unsigned char yes, unsigned char no) {
        code.push_back(BPF_JUMP(opcode, value, yes, no));
    };
    statement(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch));
    jump(BPF_JMP | BPF_JEQ | BPF_K, architecture, 1, 0);
    statement(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    statement(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr));
#if defined(__x86_64__)
    jump(BPF_JMP | BPF_JGE | BPF_K, 0x40000000U, 0, 1);
    statement(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
#endif
    const std::vector<int> denied = {
        SYS_execve, SYS_execveat, SYS_clone, SYS_clone3,
#ifdef SYS_fork
        SYS_fork,
#endif
#ifdef SYS_vfork
        SYS_vfork,
#endif
        SYS_ptrace, SYS_process_vm_readv, SYS_process_vm_writev,
        SYS_mount, SYS_umount2, SYS_pivot_root, SYS_chroot, SYS_unshare, SYS_setns,
        SYS_bpf, SYS_perf_event_open, SYS_userfaultfd,
        SYS_io_uring_setup, SYS_io_uring_enter, SYS_io_uring_register,
        SYS_open_by_handle_at, SYS_name_to_handle_at,
#ifdef SYS_chmod
        SYS_chmod,
#endif
        SYS_fchmod, SYS_fchmodat,
#ifdef SYS_fchmodat2
        SYS_fchmodat2,
#endif
#ifdef SYS_chown
        SYS_chown,
#endif
#ifdef SYS_lchown
        SYS_lchown,
#endif
        SYS_fchown, SYS_fchownat,
        SYS_setxattr, SYS_lsetxattr, SYS_fsetxattr,
        SYS_removexattr, SYS_lremovexattr, SYS_fremovexattr,
#ifdef SYS_utime
        SYS_utime,
#endif
#ifdef SYS_utimes
        SYS_utimes,
#endif
#ifdef SYS_futimesat
        SYS_futimesat,
#endif
        SYS_utimensat,
#ifdef SYS_link
        SYS_link,
#endif
#ifdef SYS_symlink
        SYS_symlink,
#endif
#ifdef SYS_rename
        SYS_rename,
#endif
#ifdef SYS_unlink
        SYS_unlink,
#endif
#ifdef SYS_mkdir
        SYS_mkdir,
#endif
#ifdef SYS_rmdir
        SYS_rmdir,
#endif
#ifdef SYS_mknod
        SYS_mknod,
#endif
        SYS_linkat, SYS_symlinkat, SYS_renameat, SYS_renameat2,
        SYS_unlinkat, SYS_mkdirat, SYS_mknodat,
        SYS_kill, SYS_tkill, SYS_tgkill, SYS_pidfd_send_signal, SYS_pidfd_getfd,
        SYS_setuid, SYS_setgid, SYS_setreuid, SYS_setregid, SYS_setresuid, SYS_setresgid,
        SYS_setfsuid, SYS_setfsgid, SYS_setgroups, SYS_capset,
        SYS_reboot, SYS_kexec_load, SYS_init_module, SYS_finit_module, SYS_delete_module,
        SYS_swapon, SYS_swapoff, SYS_acct, SYS_quotactl, SYS_settimeofday, SYS_clock_settime,
        SYS_keyctl, SYS_add_key, SYS_request_key,
        SYS_socketpair, SYS_sendmsg, SYS_recvmsg,
    };
    for (const int number : denied) {
        jump(BPF_JMP | BPF_JEQ | BPF_K, static_cast<unsigned int>(number), 0, 1);
        statement(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
    }
    // Restrict socket creation to stream IPv4, IPv6 and UNIX sockets. This
    // excludes UDP/raw/packet/netlink even on ABI9, which only mediates TCP.
    jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 0, 12);
    statement(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[0]));
    jump(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 3, 0);
    jump(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 2, 0);
    jump(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 1, 0);
    statement(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
    statement(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[1]));
    statement(BPF_ALU | BPF_AND | BPF_K, ~(static_cast<unsigned int>(SOCK_CLOEXEC | SOCK_NONBLOCK)));
    jump(BPF_JMP | BPF_JEQ | BPF_K, SOCK_STREAM, 0, 3);
    statement(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[2]));
    jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 2, 0);
    jump(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, 1, 0);
    statement(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
    statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    sock_fprog program{};
    program.len = static_cast<unsigned short>(code.size());
    program.filter = code.data();
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) < 0)
        fail_system("install seccomp filter");
}

Json failure(const char* code, const char* phase, const char* message) {
    return {{"ok", false}, {"error_code", code}, {"phase", phase}, {"error", message}};
}

#ifndef SAGA_EXECUTOR_ONLY
// Every retained descriptor is relocated before fork so the fixed child slots
// can be overwritten without accidentally clobbering another retained handle.
int relocate(int descriptor) {
    const int result = fcntl(descriptor, F_DUPFD_CLOEXEC, 6);
    const int saved = errno;
    close(descriptor);
    if (result < 0) { errno = saved; fail_system("reserve executor descriptor"); }
    return result;
}

int sealed_memfd(const char* name, const char* bytes, std::size_t size, bool executable) {
    // RLIMIT_FSIZE also applies to memfds. A coordinator may inherit a small
    // limit from its host; detect that before write() can deliver SIGXFSZ to
    // the embedding application instead of returning an execution failure.
    rlimit limit{};
    if (getrlimit(RLIMIT_FSIZE, &limit) < 0) fail_system("inspect coordinator file-size limit");
    if (limit.rlim_cur != RLIM_INFINITY && size > limit.rlim_cur)
        throw std::runtime_error("executor image or request exceeds coordinator file-size limit");
    const int raw = static_cast<int>(syscall(SYS_memfd_create, name,
        MFD_CLOEXEC | MFD_ALLOW_SEALING | (executable ? MFD_EXEC : MFD_NOEXEC_SEAL)));
    if (raw < 0) fail_system("create isolated executor image or request");
    const Fd descriptor(relocate(raw));
    std::size_t offset = 0;
    while (offset < size) {
        const auto count = write(descriptor.value, bytes + offset, size - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) fail_system("prepare executor image or request");
        offset += static_cast<std::size_t>(count);
    }
    if (lseek(descriptor.value, 0, SEEK_SET) < 0 ||
        fcntl(descriptor.value, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) < 0)
        fail_system("seal executor image or request");
    const int result = fcntl(descriptor.value, F_DUPFD_CLOEXEC, 6);
    if (result < 0) fail_system("retain sealed executor descriptor");
    return result;
}

std::string executor_loader_environment() {
    const auto address = reinterpret_cast<std::uintptr_t>(&sqlite3_open_v2);
    struct Origin { std::uintptr_t address; bool main_image = false; } origin{address};
    dl_iterate_phdr([](dl_phdr_info* image, std::size_t, void* context) {
        auto& found = *static_cast<Origin*>(context);
        if (image->dlpi_name && image->dlpi_name[0] != '\0') return 0;
        for (ElfW(Half) index = 0; index < image->dlpi_phnum; ++index) {
            const auto& segment = image->dlpi_phdr[index];
            const auto start = static_cast<std::uintptr_t>(image->dlpi_addr + segment.p_vaddr);
            if (segment.p_type == PT_LOAD && found.address >= start && found.address - start < segment.p_memsz) {
                found.main_image = true;
                return 1;
            }
        }
        return 0;
    }, &origin);
    // A statically linked SQLite has no DSO directory to pass to the loader.
    if (origin.main_image) return {};
    Dl_info information{};
    if (dladdr(reinterpret_cast<const void*>(address), &information) == 0 || !information.dli_fname)
        throw std::runtime_error("cannot identify executor SQLite dependency");
    const std::unique_ptr<char, decltype(&std::free)> canonical(realpath(information.dli_fname, nullptr), std::free);
    if (!canonical) fail_system("resolve executor SQLite dependency");
    const std::string path(canonical.get());
    const auto slash = path.find_last_of('/');
    if (slash == std::string::npos) throw std::runtime_error("executor dependency path must be absolute");
    const auto directory = path.substr(0, slash == 0 ? 1 : slash);
    // ld.so has no escaping for path separators and expands dollar tokens.
    // Never reinterpret one trusted directory as multiple search locations.
    if (directory.find_first_of(":;$") != std::string::npos)
        throw std::runtime_error("executor dependency directory cannot be represented safely");
    return "LD_LIBRARY_PATH=" + directory;
}

void ensure_single_threaded() {
    const auto close_tasks = [](DIR* directory) { closedir(directory); };
    const std::unique_ptr<DIR, decltype(close_tasks)> tasks(opendir("/proc/self/task"), close_tasks);
    if (!tasks) fail_system("inspect process threads");
    unsigned int count = 0;
    while (const auto* entry = readdir(tasks.get()))
        if (entry->d_name[0] != '.') ++count;
    if (count != 1) throw std::runtime_error("sandbox coordinator must be single-threaded");
    struct sigaction action{};
    if (sigaction(SIGCHLD, nullptr, &action) < 0) fail_system("inspect child signal handling");
    if (action.sa_handler != SIG_DFL || (action.sa_flags & SA_NOCLDWAIT))
        throw std::runtime_error("sandbox coordinator requires default SIGCHLD handling");
}

Json in_child(const Json& request, bool* started = nullptr) {
    ensure_single_threaded();
    const auto document = request.dump();
    if (document.size() > max_data) throw std::runtime_error("executor request too large");
    const Fd image(sealed_memfd("saga-executor", embedded::image, sizeof(embedded::image) - 1, true));
    const Fd input(sealed_memfd("saga-request", document.data(), document.size(), false));
    const Fd neutral(relocate(open("/dev/null", O_RDWR | O_CLOEXEC)));
    if (neutral.value < 0) fail_system("create neutral standard streams");
    int channel[2];
    if (pipe2(channel, O_CLOEXEC) < 0) fail_system("create child result pipe");
    const Fd output(channel[0]);
    Fd sender(relocate(channel[1]));
    auto loader_setting = executor_loader_environment();
    char* environment[] = {loader_setting.empty() ? nullptr : loader_setting.data(), nullptr};
    const pid_t coordinator = getpid();
    const pid_t child = fork();
    if (child < 0) fail_system("fork executor");
    if (child == 0) {
        // This branch runs only trusted setup. No capability parser or handler
        // sees the inherited address space: success must replace it with exec.
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != coordinator) _exit(125);
        struct sigaction default_action{};
        default_action.sa_handler = SIG_DFL;
        sigemptyset(&default_action.sa_mask);
        for (int number = 1; number < NSIG; ++number) {
            if (number == SIGKILL || number == SIGSTOP) continue;
            if (sigaction(number, &default_action, nullptr) < 0 && errno != EINVAL) _exit(126);
        }
        sigset_t empty_mask;
        sigemptyset(&empty_mask);
        if (sigprocmask(SIG_SETMASK, &empty_mask, nullptr) < 0 || chdir("/") < 0) _exit(126);
        if (dup3(input.value, 3, 0) < 0 || dup3(sender.value, 4, 0) < 0 ||
            dup3(image.value, 5, O_CLOEXEC) < 0) _exit(126);
        for (int stream = 0; stream < 3; ++stream)
            if (dup2(neutral.value, stream) < 0) _exit(126);
        if (syscall(SYS_close_range, 6U, ~0U, 0U) < 0) _exit(126);
        const rlimit cpu{5, 5};
        const rlimit memory{512 * 1024 * 1024, 512 * 1024 * 1024};
        const rlimit files{max_data, max_data};
        const rlimit core{0, 0};
        if (setrlimit(RLIMIT_CPU, &cpu) < 0 || setrlimit(RLIMIT_AS, &memory) < 0 ||
            setrlimit(RLIMIT_FSIZE, &files) < 0 || setrlimit(RLIMIT_CORE, &core) < 0 ||
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) _exit(126);
        char name[] = "saga-executor";
        char* argv[] = {name, nullptr};
        syscall(SYS_execveat, 5, "", argv, environment, AT_EMPTY_PATH);
        _exit(127);
    }
    if (started) *started = true;
    // Only the child may retain the result pipe writer.
    close(sender.value);
    sender.value = -1;
    struct ChildGuard {
        pid_t pid;
        bool reaped = false;
        ~ChildGuard() {
            if (!reaped) {
                kill(pid, SIGKILL);
                int status;
                while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            }
        }
    } child_guard{child};
    std::string encoded;
    std::array<char, 8192> buffer{};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    bool timed_out = false;
    bool oversized = false;
    bool read_failed = false;
    for (;;) {
        if (std::chrono::steady_clock::now() >= deadline) { timed_out = true; break; }
        pollfd descriptor{output.value, POLLIN, 0};
        const int ready = poll(&descriptor, 1, 100);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) { read_failed = true; break; }
        if (ready == 0) continue;
        const auto count = read(output.value, buffer.data(), buffer.size());
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { read_failed = true; break; }
        if (count == 0) break;
        encoded.append(buffer.data(), static_cast<std::size_t>(count));
        if (encoded.size() > max_data) { oversized = true; break; }
    }
    if (timed_out || oversized || read_failed) kill(child, SIGKILL);
    int status = 0;
    for (;;) {
        const pid_t reaped = waitpid(child, &status, WNOHANG);
        if (reaped == child) break;
        if (reaped < 0 && errno != EINTR) {
            if (errno == ECHILD) child_guard.reaped = true;
            fail_system("reap executor");
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            timed_out = true;
            kill(child, SIGKILL);
        }
        poll(nullptr, 0, 10);
    }
    child_guard.reaped = true;
    if (timed_out) return failure("executor_timeout", "execution", "executor exceeded time limit");
    if (oversized) return failure("executor_result_too_large", "execution", "executor result too large");
    if (read_failed) return failure("executor_channel_failed", "execution", "executor result channel failed");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return failure("executor_terminated", "execution", "executor terminated before completion");
    try {
        const auto result = Json::parse(encoded);
        if (!result.is_object() || !result.contains("ok") || !result.at("ok").is_boolean() ||
            (result.at("ok").get<bool>() ? !result.contains("result") :
                !result.contains("error_code") || !result.at("error_code").is_string()))
            return failure("executor_protocol_failed", "execution", "executor returned an invalid result");
        return result;
    } catch (...) {
        return failure("executor_protocol_failed", "execution", "executor returned an invalid result");
    }
}
#endif

std::string read_file(const std::string& path) {
    const Fd input(open_regular(path, O_RDONLY));
    std::string result;
    std::array<char, 8192> buffer{};
    for (;;) {
        const auto count = read(input.value, buffer.data(), buffer.size());
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) fail_system("read resource");
        if (count == 0) break;
        if (static_cast<std::size_t>(count) > max_content - result.size())
            throw std::runtime_error("file exceeds 1 MiB read limit");
        result.append(buffer.data(), static_cast<std::size_t>(count));
    }
    return result;
}

Json write_file(const std::string& path, const std::string& content) {
    if (content.size() > max_content) throw std::runtime_error("content exceeds 1 MiB write limit");
    const Fd output(open_regular(path, O_WRONLY | O_TRUNC));
    std::size_t offset = 0;
    while (offset < content.size()) {
        const auto count = write(output.value, content.data() + offset, content.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) fail_system("write resource");
        offset += static_cast<std::size_t>(count);
    }
    if (fsync(output.value) < 0) fail_system("persist resource");
    return {{"bytes_written", offset}};
}

std::string sqlite_uri(const std::string& path) {
    const char hex[] = "0123456789ABCDEF";
    std::string uri = "file:";
    for (const char raw_character : path) {
        const auto character = static_cast<unsigned char>(raw_character);
        if ((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
            (character >= '0' && character <= '9') || character == '/' || character == '-' ||
            character == '_' || character == '.') uri += static_cast<char>(character);
        else { uri += '%'; uri += hex[character >> 4]; uri += hex[character & 15]; }
    }
    return uri + "?mode=ro&immutable=1";
}

int sql_authorizer(void*, int operation, const char*, const char* name, const char*, const char*) {
    if (operation == SQLITE_SELECT || operation == SQLITE_READ || operation == SQLITE_RECURSIVE)
        return SQLITE_OK;
    if (operation == SQLITE_FUNCTION && name && std::strcmp(name, "load_extension") != 0)
        return SQLITE_OK;
    return SQLITE_DENY;
}

Json query_db(const Json& execution, const Json& arguments) {
    const auto path = text(execution, "path");
    // immutable=1 is correct only for a frozen rollback-format snapshot.
    // Repeat the Provider's checks at execution time rather than silently
    // ignoring a WAL or rollback journal created after issuance.
    {
        const Fd checked(open_regular(path, O_RDONLY));
        std::array<unsigned char, 100> header{};
        if (pread(checked.value, header.data(), header.size(), 0) != static_cast<ssize_t>(header.size()) ||
            std::memcmp(header.data(), "SQLite format 3\0", 16) != 0 || header[18] != 1 || header[19] != 1)
            throw std::runtime_error("SQLite resource must be a frozen rollback-format snapshot");
        for (const char* suffix : {"-wal", "-shm", "-journal"}) {
            struct stat attributes{};
            const auto sidecar = path + suffix;
            if (lstat(sidecar.c_str(), &attributes) == 0 || errno != ENOENT)
                throw std::runtime_error("SQLite snapshot has a sidecar or inaccessible sidecar path");
        }
    }
    sqlite3* raw_database = nullptr;
    const auto uri = sqlite_uri(path);
    const int opened = sqlite3_open_v2(uri.c_str(), &raw_database,
        SQLITE_OPEN_READONLY | SQLITE_OPEN_URI | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_NOFOLLOW, nullptr);
    const std::unique_ptr<sqlite3, decltype(&sqlite3_close)> database(raw_database, sqlite3_close);
    if (opened != SQLITE_OK) throw std::runtime_error(std::string("cannot open read-only SQLite resource: ") +
        (raw_database ? sqlite3_errmsg(raw_database) : "allocation failed") +
        " (" + std::to_string(opened) + ")");
    sqlite3_limit(database.get(), SQLITE_LIMIT_LENGTH, static_cast<int>(max_content));
    sqlite3_limit(database.get(), SQLITE_LIMIT_SQL_LENGTH, 64 * 1024);
    if (sqlite3_exec(database.get(), "PRAGMA temp_store=MEMORY", nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("cannot configure SQLite memory temporary store");
    sqlite3_set_authorizer(database.get(), sql_authorizer, nullptr);
    const auto sql = text(execution, "sql");
    sqlite3_stmt* raw_statement = nullptr;
    const char* tail = nullptr;
    const int prepared = sqlite3_prepare_v2(database.get(), sql.c_str(), static_cast<int>(sql.size()), &raw_statement, &tail);
    const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> statement(raw_statement, sqlite3_finalize);
    if (prepared != SQLITE_OK || !statement || !sqlite3_stmt_readonly(statement.get()))
        throw std::runtime_error("registered SQL is not an authorized read-only statement");
    while (tail && *tail && std::isspace(static_cast<unsigned char>(*tail))) ++tail;
    if (tail && *tail) throw std::runtime_error("registered SQL contains multiple statements");
    const auto& parameters = arguments.at("parameters");
    if (!parameters.is_array() || sqlite3_bind_parameter_count(statement.get()) != static_cast<int>(parameters.size()))
        throw std::runtime_error("SQL parameter count differs from registered query");
    for (std::size_t index = 0; index < parameters.size(); ++index) {
        const auto& parameter = parameters[index];
        const int slot = static_cast<int>(index + 1);
        int bound = SQLITE_MISUSE;
        if (parameter.is_null()) bound = sqlite3_bind_null(statement.get(), slot);
        else if (parameter.is_boolean()) bound = sqlite3_bind_int(statement.get(), slot, parameter.get<bool>());
        else if (parameter.is_number_integer()) bound = sqlite3_bind_int64(statement.get(), slot, parameter.get<sqlite3_int64>());
        else if (parameter.is_number_float()) bound = sqlite3_bind_double(statement.get(), slot, parameter.get<double>());
        else if (parameter.is_string()) {
            const auto& value = parameter.get_ref<const std::string&>();
            if (value.size() > max_content) throw std::runtime_error("SQL parameter too large");
            bound = sqlite3_bind_text(statement.get(), slot, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT);
        }
        if (bound != SQLITE_OK) throw std::runtime_error("unsupported SQL parameter");
    }
    Json columns = Json::array();
    Json rows = Json::array();
    const int width = sqlite3_column_count(statement.get());
    for (int column = 0; column < width; ++column) columns.push_back(sqlite3_column_name(statement.get(), column));
    int stepped = SQLITE_OK;
    std::size_t row_bytes = 0;
    while ((stepped = sqlite3_step(statement.get())) == SQLITE_ROW) {
        if (rows.size() >= 1000) throw std::runtime_error("query exceeds 1000 row limit");
        Json row = Json::array();
        for (int column = 0; column < width; ++column) {
            switch (sqlite3_column_type(statement.get(), column)) {
                case SQLITE_NULL: row.push_back(nullptr); break;
                case SQLITE_INTEGER: row.push_back(sqlite3_column_int64(statement.get(), column)); break;
                case SQLITE_FLOAT: {
                    const auto value = sqlite3_column_double(statement.get(), column);
                    if (!std::isfinite(value))
                        throw std::runtime_error("nonfinite SQL results cannot be represented as JSON numbers");
                    row.push_back(value);
                    break;
                }
                case SQLITE_TEXT: {
                    const auto* bytes = sqlite3_column_text(statement.get(), column);
                    row.push_back(std::string(reinterpret_cast<const char*>(bytes),
                        static_cast<std::size_t>(sqlite3_column_bytes(statement.get(), column))));
                    break;
                }
                default: throw std::runtime_error("BLOB results require a separately registered handler");
            }
        }
        row_bytes += row.dump(-1, ' ', false, Json::error_handler_t::replace).size();
        if (row_bytes > max_content) throw std::runtime_error("query exceeds 1 MiB result limit");
        rows.push_back(std::move(row));
    }
    if (stepped != SQLITE_DONE) throw std::runtime_error("registered SQL execution failed");
    return {{"columns", columns}, {"rows", rows}};
}

struct HttpTarget {
    std::string host;
    std::string host_header;
    std::string path;
    std::uint16_t port = 80;
    int family = AF_INET;
};

HttpTarget parse_http(const std::string& url) {
    if (url.rfind("http://", 0) != 0 || url.find_first_of("\r\n\t #") != std::string::npos ||
        url.find('\0') != std::string::npos)
        throw std::runtime_error("HTTP resource must use numeric loopback plain HTTP");
    const auto slash = url.find('/', 7);
    const auto authority = url.substr(7, slash == std::string::npos ? std::string::npos : slash - 7);
    if (authority.empty() || authority.find('@') != std::string::npos)
        throw std::runtime_error("invalid HTTP authority");
    HttpTarget target;
    target.path = slash == std::string::npos ? "/" : url.substr(slash);
    target.host_header = authority;
    std::string port;
    if (authority[0] == '[') {
        const auto end = authority.find(']');
        if (end == std::string::npos) throw std::runtime_error("invalid IPv6 authority");
        target.host = authority.substr(1, end - 1);
        target.family = AF_INET6;
        if (end + 1 < authority.size()) {
            if (authority[end + 1] != ':') throw std::runtime_error("invalid HTTP port");
            port = authority.substr(end + 2);
        }
        in6_addr address{};
        if (inet_pton(AF_INET6, target.host.c_str(), &address) != 1 || !IN6_IS_ADDR_LOOPBACK(&address))
            throw std::runtime_error("HTTP IPv6 host must be ::1");
    } else {
        const auto delimiter = authority.find(':');
        target.host = authority.substr(0, delimiter);
        if (delimiter != std::string::npos) port = authority.substr(delimiter + 1);
        in_addr address{};
        if (inet_pton(AF_INET, target.host.c_str(), &address) != 1 || (ntohl(address.s_addr) >> 24) != 127)
            throw std::runtime_error("HTTP IPv4 host must be in 127.0.0.0/8");
    }
    if (!port.empty()) {
        if (port.find_first_not_of("0123456789") != std::string::npos || port.size() > 5)
            throw std::runtime_error("invalid HTTP port");
        const auto parsed = std::stoul(port);
        if (parsed == 0 || parsed > 65535) throw std::runtime_error("HTTP port out of range");
        target.port = static_cast<std::uint16_t>(parsed);
    } else if (authority.back() == ':') throw std::runtime_error("empty HTTP port");
    return target;
}

int connect_tcp(const std::string& host, std::uint16_t port, int family) {
    const int connection = socket(family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (connection < 0) return -1;
    timeval timeout{3, 0};
    setsockopt(connection, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(connection, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    int status;
    if (family == AF_INET) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        if (inet_pton(AF_INET, host.c_str(), &address.sin_addr) != 1) { close(connection); errno = EINVAL; return -1; }
        status = connect(connection, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    } else {
        sockaddr_in6 address{};
        address.sin6_family = AF_INET6;
        address.sin6_port = htons(port);
        if (inet_pton(AF_INET6, host.c_str(), &address.sin6_addr) != 1) { close(connection); errno = EINVAL; return -1; }
        status = connect(connection, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    }
    if (status < 0) { const int error = errno; close(connection); errno = error; return -1; }
    return connection;
}

Json http_response(const std::string& response) {
    std::size_t start = 0;
    // Informational responses precede the final response, never its body.
    for (unsigned int informational = 0; informational <= 16; ++informational) {
        const auto end = response.find("\r\n\r\n", start);
        const auto line_end = response.find("\r\n", start);
        if (end == std::string::npos || line_end == std::string::npos || end - start > 65536)
            throw std::runtime_error("invalid HTTP response headers");
        const auto line = response.substr(start, line_end - start);
        if (line.size() < 13 || (line.compare(0, 8, "HTTP/1.0") != 0 && line.compare(0, 8, "HTTP/1.1") != 0) ||
            line[8] != ' ' || line[12] != ' ' || line.substr(9, 3).find_first_not_of("0123456789") != std::string::npos)
            throw std::runtime_error("invalid HTTP status line");
        for (std::size_t index = 13; index < line.size(); ++index) {
            const auto character = static_cast<unsigned char>(line[index]);
            if ((character < 32 && character != '\t') || character == 127)
                throw std::runtime_error("invalid HTTP reason phrase");
        }
        const int status = (line[9] - '0') * 100 + (line[10] - '0') * 10 + line[11] - '0';
        if (status < 100 || status > 599 || status == 101)
            throw std::runtime_error("unsupported HTTP status");
        bool has_length = false;
        std::size_t content_length = 0;
        for (auto cursor = line_end + 2; cursor < end;) {
            const auto next = response.find("\r\n", cursor);
            if (next == std::string::npos || next > end)
                throw std::runtime_error("invalid HTTP header line");
            const auto header = response.substr(cursor, next - cursor);
            const auto colon = header.find(':');
            if (colon == std::string::npos || colon == 0 ||
                header.substr(0, colon).find_first_not_of("!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") != std::string::npos)
                throw std::runtime_error("invalid HTTP header name");
            for (std::size_t index = colon + 1; index < header.size(); ++index) {
                const auto character = static_cast<unsigned char>(header[index]);
                if ((character < 32 && character != '\t') || character == 127)
                    throw std::runtime_error("invalid HTTP header value");
            }
            auto name = header.substr(0, colon);
            for (char& character : name)
                if (character >= 'A' && character <= 'Z') character += 'a' - 'A';
            if (name == "transfer-encoding")
                throw std::runtime_error("HTTP transfer encoding is unsupported by this registered handler");
            if (name == "content-length") {
                const auto value = header.substr(colon + 1);
                std::size_t item = 0;
                for (;;) {
                    const auto comma = value.find(',', item);
                    const auto part = value.substr(item, comma == std::string::npos ? comma : comma - item);
                    const auto first = part.find_first_not_of(" \t");
                    const auto last = part.find_last_not_of(" \t");
                    if (first == std::string::npos)
                        throw std::runtime_error("empty HTTP content length");
                    std::size_t length = 0;
                    for (auto index = first; index <= last; ++index) {
                        const auto character = part[index];
                        const auto maximum = status == 304 ? std::numeric_limits<std::size_t>::max() : max_content;
                        if (character < '0' || character > '9' ||
                            length > (maximum - static_cast<std::size_t>(character - '0')) / 10)
                            throw std::runtime_error("invalid or excessive HTTP content length");
                        length = length * 10 + static_cast<std::size_t>(character - '0');
                    }
                    if (has_length && content_length != length)
                        throw std::runtime_error("conflicting HTTP content lengths");
                    content_length = length;
                    has_length = true;
                    if (comma == std::string::npos) break;
                    item = comma + 1;
                }
            }
            cursor = next + 2;
        }
        const auto body_start = end + 4;
        if (status < 200) {
            if (has_length) throw std::runtime_error("informational response has a content length");
            start = body_start;
            continue;
        }
        const auto actual_length = response.size() - body_start;
        if (status == 204 || status == 304) {
            if (actual_length != 0 || (status == 204 && has_length))
                throw std::runtime_error("body forbidden for HTTP status");
        } else if ((has_length && actual_length != content_length) || (status == 205 && actual_length != 0)) {
            throw std::runtime_error("incomplete or excessive HTTP response body");
        }
        return {{"status", status}, {"body", response.substr(body_start)}};
    }
    throw std::runtime_error("too many informational HTTP responses");
}

Json http_get(const std::string& url) {
    const auto target = parse_http(url);
    const Fd connection(connect_tcp(target.host, target.port, target.family));
    if (connection.value < 0) fail_system("connect HTTP resource");
    const auto request = "GET " + target.path + " HTTP/1.0\r\nHost: " + target.host_header +
        "\r\nConnection: close\r\nAccept: */*\r\n\r\n";
    std::size_t offset = 0;
    while (offset < request.size()) {
        const auto count = send(connection.value, request.data() + offset, request.size() - offset, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) fail_system("send HTTP request");
        offset += static_cast<std::size_t>(count);
    }
    std::string response;
    std::array<char, 8192> buffer{};
    for (;;) {
        const auto count = recv(connection.value, buffer.data(), buffer.size(), 0);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) fail_system("read HTTP response");
        if (count == 0) break;
        if (static_cast<std::size_t>(count) > max_content - response.size())
            throw std::runtime_error("HTTP response exceeds 1 MiB limit");
        response.append(buffer.data(), static_cast<std::size_t>(count));
    }
    return http_response(response);
}

Json capability_sandbox(const Json& capability) {
    if (!capability.is_object() || capability.size() != 6)
        throw std::runtime_error("capability must contain exactly six registered fields");
    const auto tool = text(capability, "tool");
    const auto& execution = capability.at("execution");
    const auto& arguments = capability.at("arguments");
    if (!execution.is_object() || !arguments.is_object()) throw std::runtime_error("invalid capability");
    if (text(capability, "resource") != text(arguments, "resource"))
        throw std::runtime_error("resource differs from signed arguments");
    const auto operation = text(capability, "operation");
    if ((tool == "read_file" && operation != "read") ||
        (tool == "write_file" && operation != "write") ||
        (tool == "query_db" && operation != "query") ||
        (tool == "http_get" && operation != "get"))
        throw std::runtime_error("operation differs from registered handler");
    Json expected = {{"paths", Json::array()}, {"tcp_ports", Json::array()}};
    if (tool == "read_file" || tool == "write_file" || tool == "query_db") {
        const std::size_t argument_count = tool == "query_db" ? 3 : tool == "write_file" ? 2 : 1;
        const std::size_t execution_count = tool == "query_db" ? 2 : 1;
        if (arguments.size() != argument_count || execution.size() != execution_count)
            throw std::runtime_error("extra or missing registered handler fields");
        if (tool == "query_db" && (text(arguments, "query").empty() || !arguments.at("parameters").is_array()))
            throw std::runtime_error("invalid registered query arguments");
        expected["paths"].push_back({{"path", text(execution, "path")},
            {"access", tool == "write_file" ? "write" : "read"}});
        if (tool == "write_file" && arguments.at("content").get_ref<const std::string&>().size() > max_content)
            throw std::runtime_error("content exceeds 1 MiB write limit");
    } else if (tool == "http_get") {
        if (arguments.size() != 1 || execution.size() != 1)
            throw std::runtime_error("extra or missing HTTP handler fields");
        expected["tcp_ports"].push_back(parse_http(text(execution, "url")).port);
    } else throw std::runtime_error("unregistered executor handler");
    if (capability.at("sandbox") != expected)
        throw std::runtime_error("sandbox grants differ from exact handler requirements");
    return expected;
}

[[maybe_unused]] Json probe_attempt(const Json& attempt) {
    const auto kind = text(attempt, "kind");
    int status = -1;
    errno = 0;
    if (kind == "read") {
        status = open(text(attempt, "path").c_str(), O_RDONLY | O_CLOEXEC);
        if (status >= 0) close(status);
    } else if (kind == "write") {
        status = open(text(attempt, "path").c_str(), O_WRONLY | O_CLOEXEC);
        if (status >= 0) {
            const auto content = attempt.value("content", std::string("probe"));
            const auto count = write(status, content.data(), content.size());
            const int saved = errno;
            close(status);
            if (count < 0) { status = -1; errno = saved; }
        }
    } else if (kind == "tcp_connect") {
        const auto host = text(attempt, "host");
        const auto port = attempt.at("port").get<int>();
        if (port <= 0 || port > 65535) throw std::runtime_error("probe port out of range");
        status = connect_tcp(host, static_cast<std::uint16_t>(port), host.find(':') == std::string::npos ? AF_INET : AF_INET6);
        if (status >= 0) close(status);
    } else if (kind == "unix_connect" || kind == "abstract_unix_connect") {
        const Fd connection(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
        if (connection.value >= 0) {
            sockaddr_un address{};
            address.sun_family = AF_UNIX;
            const auto name = text(attempt, kind == "unix_connect" ? "path" : "name");
            if (name.size() >= sizeof(address.sun_path) - 1) throw std::runtime_error("probe UNIX address too long");
            const auto start = kind == "unix_connect" ? 0U : 1U;
            std::memcpy(address.sun_path + start, name.data(), name.size());
            const auto length = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + name.size() + 1);
            status = connect(connection.value, reinterpret_cast<sockaddr*>(&address), length);
        }
    } else if (kind == "udp_socket") {
        status = socket(AF_INET, SOCK_DGRAM, 0);
        if (status >= 0) close(status);
    } else if (kind == "fork") {
        status = static_cast<int>(syscall(SYS_clone, SIGCHLD, nullptr, nullptr, nullptr, 0));
        if (status == 0) _exit(126);
        if (status > 0) { int child_status; waitpid(status, &child_status, 0); }
    } else if (kind == "chmod") {
        status = chmod(text(attempt, "path").c_str(), 0600);
    } else if (kind == "tcp_bind") {
        const Fd connection(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
        if (connection.value >= 0) {
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            address.sin_port = htons(static_cast<std::uint16_t>(attempt.value("port", 0)));
            status = bind(connection.value, reinterpret_cast<sockaddr*>(&address), sizeof(address));
        }
    } else if (kind == "signal") {
        status = kill(attempt.at("pid").get<pid_t>(), attempt.value("signal", 0));
    } else if (kind == "exec") {
        char program[] = "/bin/true";
        char* argv[] = {program, nullptr};
        char* env[] = {nullptr};
        status = execve(program, argv, env);
    } else if (kind == "memory_mapping") {
        const auto& raw_address = attempt.at("address");
        if (!raw_address.is_number_integer() ||
            (!raw_address.is_number_unsigned() && raw_address.get<std::int64_t>() < 0))
            throw std::runtime_error("invalid probe memory address");
        const auto address = raw_address.get<std::uint64_t>();
        const auto page = static_cast<std::uint64_t>(sysconf(_SC_PAGESIZE));
        if (address == 0 || address > std::numeric_limits<std::uintptr_t>::max() || address % page != 0)
            throw std::runtime_error("unaligned probe memory address");
        unsigned char resident = 0;
        status = mincore(reinterpret_cast<void*>(static_cast<std::uintptr_t>(address)),
            static_cast<std::size_t>(page), &resident);
    } else if (kind == "descriptor") {
        status = fcntl(attempt.at("fd").get<int>(), F_GETFD);
    } else if (kind == "environment") {
        status = std::getenv(text(attempt, "name").c_str()) ? 0 : -1;
        if (status < 0) errno = ENOENT;
    } else throw std::runtime_error("unregistered probe operation");
    const int error = status < 0 ? errno : 0;
    return {{"kind", kind}, {"ok", status >= 0}, {"errno", error}};
}
}

Json run_handler(const Json& capability) {
    const auto tool = text(capability, "tool");
    const auto& execution = capability.at("execution");
    const auto& arguments = capability.at("arguments");
    if (tool == "read_file") return Json{{"content", read_file(text(execution, "path"))}};
    if (tool == "write_file") return write_file(text(execution, "path"), arguments.at("content").get<std::string>());
    if (tool == "query_db") return query_db(execution, arguments);
    return http_get(text(execution, "url"));
}

#ifdef SAGA_EXECUTOR_ONLY
int executor_main() noexcept {
    // exec resets dumpable. Set it again before accepting any request data.
    // The only possible initial environment value is the coordinator-selected
    // SQLite DSO directory used by the loader. Handlers receive no environment.
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0 || clearenv() != 0) return 126;
    Json result;
    const char* phase = "sandbox_setup";
    try {
        std::string document;
        std::array<char, 8192> buffer{};
        for (;;) {
            const auto count = read(3, buffer.data(), buffer.size());
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) throw std::runtime_error("request channel failed");
            if (count == 0) break;
            if (static_cast<std::size_t>(count) > max_data - document.size())
                throw std::runtime_error("request too large");
            document.append(buffer.data(), static_cast<std::size_t>(count));
        }
        close(3);
        const auto request = Json::parse(document);
        const auto mode = text(request, "mode");
        const auto& data = request.at("data");
        const auto sandbox = mode == "execute" ? capability_sandbox(data) : data.at("sandbox");
        if (mode != "execute" && mode != "probe") throw std::runtime_error("invalid executor mode");
        install_landlock(sandbox);
        install_seccomp();
        phase = "execution";
        Json output;
        if (mode == "execute") output = run_handler(data);
        else {
            Json attempts = Json::array();
            if (!data.at("attempts").is_array() || data.at("attempts").size() > 100)
                throw std::runtime_error("probe requires at most 100 attempts");
            for (const auto& attempt : data.at("attempts")) attempts.push_back(probe_attempt(attempt));
            output = {{"attempts", attempts}};
        }
        result = {{"ok", true}, {"result", output}};
    } catch (...) {
        result = std::strcmp(phase, "execution") == 0
            ? failure("execution_failed", "execution", "registered handler execution failed")
            : failure("sandbox_setup_failed", "sandbox_setup", "executor sandbox setup failed");
    }
    std::string encoded;
    try { encoded = result.dump(); }
    catch (...) { return 126; }
    if (encoded.size() > max_data)
        encoded = R"({"ok":false,"error_code":"executor_result_too_large","phase":"execution","error":"executor result too large"})";
    std::size_t offset = 0;
    while (offset < encoded.size()) {
        const auto count = write(4, encoded.data() + offset, encoded.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 126;
        offset += static_cast<std::size_t>(count);
    }
    close(4);
    return 0;
}
#else
Json execute_child(const Json& capability, bool& executor_started) {
    capability_sandbox(capability);
    return in_child({{"mode", "execute"}, {"data", capability}}, &executor_started);
}

Json probe_child(const Json& specification) {
    const auto result = in_child({{"mode", "probe"}, {"data", specification}});
    Json output = result;
    output["landlock_abi"] = landlock_abi();
    if (output.value("ok", false)) {
        output["attempts"] = output.at("result").at("attempts");
        output.erase("result");
    }
    return output;
}
#endif
} // namespace detail
} // namespace saga
