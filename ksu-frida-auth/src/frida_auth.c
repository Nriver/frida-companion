/*
 * frida-auth shim
 *
 * Loaded into frida-server through LD_PRELOAD. It enforces a per-UID
 * allowlist before frida-server is allowed to inspect another process.
 *
 * The allowlist lives at /data/adb/frida-auth/allow.list and contains one
 * entry per line:
 *
 *     10554 com.example.app
 *
 * Only the numeric UID is used here. UID 0 (root) and 2000 (shell) are always
 * allowed so frida-server can talk to its own helpers and the ADB transport.
 *
 * This file is intentionally dependency-free (libc, libdl, liblog only).
 */

#define _GNU_SOURCE

#include <android/log.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define TAG "frida-auth"
#define ALLOW_FILE "/data/adb/frida-auth/allow.list"

/*
 * Only the root frida-server / frida-helper processes are subject to the
 * allowlist. If a spawned app happens to inherit LD_PRELOAD, we go dormant so
 * that we don't alter the app's own behaviour or show up as an active hook.
 */
static int g_active = 1;

__attribute__((constructor)) static void frida_auth_init(void)
{
    if (getuid() != 0) {
        g_active = 0;
        unsetenv("LD_PRELOAD");
    }
}

static uid_t read_process_uid(pid_t pid)
{
    char path[64];
    char line[256];
    uid_t uid = (uid_t)-1;
    FILE *f;

    if (pid <= 0)
        return (uid_t)-1;

    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    f = fopen(path, "re");
    if (f == NULL)
        return (uid_t)-1;

    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, "Uid:", 4) == 0) {
            unsigned long value = 0;
            if (sscanf(line + 4, "%lu", &value) == 1)
                uid = (uid_t)value;
            break;
        }
    }

    fclose(f);
    return uid;
}

static int parse_uid_line(const char *line, uid_t *out)
{
    const char *p = line;
    char *end = NULL;
    long value;

    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '\0' || *p == '\n' || *p == '#')
        return 0;

    errno = 0;
    value = strtol(p, &end, 10);
    if (errno != 0 || end == p || value < 0)
        return 0;

    *out = (uid_t)value;
    return 1;
}

static int uid_is_allowed(uid_t uid)
{
    char line[256];
    FILE *f;

    if (uid == 0 || uid == 2000)
        return 1;

    f = fopen(ALLOW_FILE, "re");
    if (f == NULL)
        return 0;

    while (fgets(line, sizeof(line), f) != NULL) {
        uid_t allowed;
        if (parse_uid_line(line, &allowed) && allowed == uid) {
            fclose(f);
            return 1;
        }
    }

    fclose(f);
    return 0;
}

static int target_is_allowed(pid_t pid, const char *operation)
{
    uid_t uid;

    if (pid <= 0)
        return 1;

    uid = read_process_uid(pid);
    if (uid == (uid_t)-1)
        return 1;

    if (uid_is_allowed(uid))
        return 1;

    __android_log_print(ANDROID_LOG_WARN, TAG,
                        "denied %s on pid=%d uid=%u", operation, (int)pid,
                        (unsigned)uid);
    return 0;
}

/* ----------------------------- ptrace ----------------------------- */

typedef long (*ptrace_fn)(int, ...);
static ptrace_fn real_ptrace;

long ptrace(int request, ...)
{
    va_list ap;
    pid_t pid;
    void *addr;
    void *data;
    int check = 0;

    if (real_ptrace == NULL)
        real_ptrace = (ptrace_fn)dlsym(RTLD_NEXT, "ptrace");
    if (real_ptrace == NULL) {
        errno = ENOSYS;
        return -1;
    }

    va_start(ap, request);
    pid = va_arg(ap, pid_t);
    addr = va_arg(ap, void *);
    data = va_arg(ap, void *);
    va_end(ap);

    if (!g_active)
        return real_ptrace(request, pid, addr, data);

    switch ((int)request) {
    case PTRACE_ATTACH:
    case PTRACE_SEIZE:
    case PTRACE_INTERRUPT:
    case PTRACE_SETOPTIONS:
        check = 1;
        break;
    default:
        break;
    }

    if (check && !target_is_allowed(pid, "ptrace")) {
        errno = EPERM;
        return -1;
    }

    return real_ptrace(request, pid, addr, data);
}

/* --------------------------- pidfd_open --------------------------- */

typedef int (*pidfd_open_fn)(pid_t, unsigned int);
static pidfd_open_fn real_pidfd_open;

int pidfd_open(pid_t pid, unsigned int flags)
{
    if (real_pidfd_open == NULL)
        real_pidfd_open = (pidfd_open_fn)dlsym(RTLD_NEXT, "pidfd_open");
    if (real_pidfd_open == NULL) {
        errno = ENOSYS;
        return -1;
    }

    if (!g_active)
        return real_pidfd_open(pid, flags);

    if (!target_is_allowed(pid, "pidfd_open")) {
        errno = EPERM;
        return -1;
    }

    return real_pidfd_open(pid, flags);
}

/* --------------------------- pidfd_getfd -------------------------- */

typedef int (*pidfd_getfd_fn)(int, int, unsigned int);
static pidfd_getfd_fn real_pidfd_getfd;

static pid_t pid_from_pidfd(int pidfd)
{
    char path[64];
    char line[256];
    pid_t pid = -1;
    FILE *f;

    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", pidfd);
    f = fopen(path, "re");
    if (f == NULL)
        return -1;

    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, "Pid:", 4) == 0) {
            long value = strtol(line + 4, NULL, 10);
            if (value > 0)
                pid = (pid_t)value;
            break;
        }
    }

    fclose(f);
    return pid;
}

int pidfd_getfd(int pidfd, int targetfd, unsigned int flags)
{
    pid_t pid;

    if (real_pidfd_getfd == NULL)
        real_pidfd_getfd = (pidfd_getfd_fn)dlsym(RTLD_NEXT, "pidfd_getfd");
    if (real_pidfd_getfd == NULL) {
        errno = ENOSYS;
        return -1;
    }

    if (!g_active)
        return real_pidfd_getfd(pidfd, targetfd, flags);

    pid = pid_from_pidfd(pidfd);
    if (pid > 0 && !target_is_allowed(pid, "pidfd_getfd")) {
        errno = EPERM;
        return -1;
    }

    return real_pidfd_getfd(pidfd, targetfd, flags);
}

/* ------------------------- process_vm_* --------------------------- */

typedef ssize_t (*process_vm_readv_fn)(pid_t, const struct iovec *,
                                       unsigned long, const struct iovec *,
                                       unsigned long, unsigned long);
typedef ssize_t (*process_vm_writev_fn)(pid_t, const struct iovec *,
                                        unsigned long, const struct iovec *,
                                        unsigned long, unsigned long);

static process_vm_readv_fn real_process_vm_readv;
static process_vm_writev_fn real_process_vm_writev;

ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov,
                         unsigned long liovcnt, const struct iovec *remote_iov,
                         unsigned long riovcnt, unsigned long flags)
{
    if (real_process_vm_readv == NULL)
        real_process_vm_readv =
            (process_vm_readv_fn)dlsym(RTLD_NEXT, "process_vm_readv");
    if (real_process_vm_readv == NULL) {
        errno = ENOSYS;
        return -1;
    }

    if (!g_active)
        return real_process_vm_readv(pid, local_iov, liovcnt, remote_iov,
                                     riovcnt, flags);

    if (!target_is_allowed(pid, "process_vm_readv")) {
        errno = EPERM;
        return -1;
    }

    return real_process_vm_readv(pid, local_iov, liovcnt, remote_iov,
                                 riovcnt, flags);
}

ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov,
                          unsigned long liovcnt,
                          const struct iovec *remote_iov,
                          unsigned long riovcnt, unsigned long flags)
{
    if (real_process_vm_writev == NULL)
        real_process_vm_writev =
            (process_vm_writev_fn)dlsym(RTLD_NEXT, "process_vm_writev");
    if (real_process_vm_writev == NULL) {
        errno = ENOSYS;
        return -1;
    }

    if (!g_active)
        return real_process_vm_writev(pid, local_iov, liovcnt, remote_iov,
                                      riovcnt, flags);

    if (!target_is_allowed(pid, "process_vm_writev")) {
        errno = EPERM;
        return -1;
    }

    return real_process_vm_writev(pid, local_iov, liovcnt, remote_iov,
                                  riovcnt, flags);
}

/* ------------------------ /proc/<pid>/mem ------------------------- */

static int path_has_target_pid(const char *path, pid_t *out)
{
    const char *cursor;
    char *end = NULL;
    long pid;

    if (path == NULL)
        return 0;
    if (strncmp(path, "/proc/", 6) != 0)
        return 0;

    cursor = path + 6;
    if (*cursor < '0' || *cursor > '9')
        return 0;

    pid = strtol(cursor, &end, 10);
    if (end == cursor || pid <= 0)
        return 0;
    if (strcmp(end, "/mem") != 0)
        return 0;

    *out = (pid_t)pid;
    return 1;
}

typedef int (*open_fn)(const char *, int, ...);
static open_fn real_open;

int open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    pid_t pid;

    if (real_open == NULL)
        real_open = (open_fn)dlsym(RTLD_NEXT, "open");
    if (real_open == NULL) {
        errno = ENOSYS;
        return -1;
    }

    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    if (!g_active)
        return real_open(path, flags, mode);

    if (path_has_target_pid(path, &pid) &&
        !target_is_allowed(pid, "open /proc/pid/mem")) {
        errno = EPERM;
        return -1;
    }

    return real_open(path, flags, mode);
}

typedef int (*openat_fn)(int, const char *, int, ...);
static openat_fn real_openat;

int openat(int dirfd, const char *path, int flags, ...)
{
    mode_t mode = 0;
    pid_t pid;

    if (real_openat == NULL)
        real_openat = (openat_fn)dlsym(RTLD_NEXT, "openat");
    if (real_openat == NULL) {
        errno = ENOSYS;
        return -1;
    }

    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    if (!g_active)
        return real_openat(dirfd, path, flags, mode);

    if (path_has_target_pid(path, &pid) &&
        !target_is_allowed(pid, "openat /proc/pid/mem")) {
        errno = EPERM;
        return -1;
    }

    return real_openat(dirfd, path, flags, mode);
}
