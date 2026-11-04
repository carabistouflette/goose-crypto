/* SPDX-License-Identifier: Apache-2.0 */
/* Test-only syscall/ABI faults; never linked into production. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
typedef struct { const uint8_t *data; int64_t len; } gd_input;
typedef struct { int64_t *data; int64_t len; } gd_meta;
ssize_t __real_write(int, const void *, size_t);
int __real_fdatasync(int);
int __real_fstat(int, struct stat *);
int __real_close(int);
int __real_unlinkat(int, const char *, int);
int64_t __real_gd_signals_start(void);
int64_t __real_gf_root_rename(int64_t, int64_t, gd_input, gd_input, int64_t, gd_meta);
static int write_calls, injected_close_fd = -1;
static int mode(const char *name) {
    const char *selected = getenv("GOOSE_DOWNLOAD_FAULT");
    return selected && strcmp(selected, name) == 0;
}
static int staging_fd(int fd) {
    const char *expected = getenv("GOOSE_DOWNLOAD_STAGING");
    char link[64], target[4096];
    if (!expected) return 0;
    int count = snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    if (count < 0 || (size_t)count >= sizeof link) return 0;
    ssize_t n = readlink(link, target, sizeof target - 1);
    if (n < 0) return 0;
    target[n] = 0;
    return strcmp(target, expected) == 0;
}
ssize_t __wrap_write(int fd, const void *data, size_t size) {
    if (staging_fd(fd)) {
        if (mode("write-zero")) return 0;
        if (mode("write-enospc")) {
            if (write_calls++) { errno = ENOSPC; return -1; }
            if (size > 1) size /= 2;
        }
    }
    return __real_write(fd, data, size);
}
int __wrap_fdatasync(int fd) {
    if (staging_fd(fd)) {
        if (mode("sync")) { errno = EIO; return -1; }
        if (mode("cancel-before-publish")) { for (int i = 0; i < 32; ++i) raise(SIGINT); }
    }
    return __real_fdatasync(fd);
}
int __wrap_fstat(int fd, struct stat *info) {
    if (mode("create-fstat") && staging_fd(fd)) { errno = EIO; return -1; }
    return __real_fstat(fd, info);
}
int __wrap_close(int fd) {
    if (mode("close") && fd == injected_close_fd && fcntl(fd, F_GETFD) < 0 && errno == EBADF) {
        fputs("download fixture detected retried consumed File close\n", stderr); exit(91);
    }
    if (mode("close") && staging_fd(fd)) {
        injected_close_fd = fd;
        int rc = __real_close(fd);
        if (rc == 0) { errno = EINTR; return -1; }
        return rc;
    }
    return __real_close(fd);
}
int __wrap_unlinkat(int dir, const char *leaf, int flags) {
    const char *expected = getenv("GOOSE_DOWNLOAD_STAGING_LEAF");
    if (mode("unlink") && expected && strcmp(leaf, expected) == 0) { errno = EACCES; return -1; }
    return __real_unlinkat(dir, leaf, flags);
}
int64_t __wrap_gf_root_rename(int64_t context, int64_t root, gd_input from,
                            gd_input to, int64_t flags, gd_meta meta) {
    if (flags != 3 || meta.len != 4 || !meta.data) {
        fputs("download fixture rejected unexpected publication ABI\n", stderr); exit(90);
    }
    if (mode("rename-not-attempted") || mode("rename-unknown")) {
        memset(meta.data, 0, 4 * sizeof *meta.data);
        meta.data[0] = EIO;
        meta.data[1] = mode("rename-unknown") ? 2 : 0;
        return 4; /* GF_SYSTEM in the explicitly pinned FS private ABI. */
    }
    if (mode("race-final")) {
        const char *target = getenv("GOOSE_DOWNLOAD_FINAL");
        if (!target) exit(90);
        int fd = open(target, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0 || __real_write(fd, "preserve", 8) != 8 || __real_close(fd)) exit(90);
    }
    if (mode("cancel-after-boundary")) raise(SIGINT);
    int64_t result = __real_gf_root_rename(context, root, from, to, flags, meta);
    if (result == 0 && (mode("rename-unknown-moved") || mode("rename-applied-error") || mode("rename-applied-close"))) {
        meta.data[0] = EIO;
        meta.data[1] = mode("rename-unknown-moved") ? 2 : 1;
        meta.data[2] = mode("rename-applied-close") ? 1 : 0;
        meta.data[3] = mode("rename-applied-close") ? EINTR : 0;
        return 4;
    }
    return result;
}
int64_t gd_test_open_fds(void) {
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return -1;
    int64_t count = -1; /* Exclude directory descriptor itself. */
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) ++count;
    }
    if (closedir(directory)) return -1;
    return count;
}

int64_t __wrap_gd_signals_start(void) {
    int64_t result = __real_gd_signals_start();
    if (result == 0 && mode("cancel-at-start")) {
        for (int i = 0; i < 32; ++i) raise(SIGTERM);
    }
    return result;
}
int64_t __real_gf_root_close(int64_t, int64_t, gd_meta);
int64_t __wrap_gf_root_close(int64_t context, int64_t root, gd_meta meta) {
    int64_t result = __real_gf_root_close(context, root, meta);
    if (result == 0 && mode("root-close")) { meta.data[0] = EIO; return 4; }
    return result;
}
int64_t __real_gf_context_close(int64_t, gd_meta);
int64_t __wrap_gf_context_close(int64_t context, gd_meta meta) {
    int64_t result = __real_gf_context_close(context, meta);
    if (result == 0 && mode("context-close")) { meta.data[0] = EIO; return 4; }
    return result;
}
int64_t __real_gh_stream_close(int64_t, gd_meta);
int64_t __wrap_gh_stream_close(int64_t handle, gd_meta meta) {
    int64_t result = __real_gh_stream_close(handle, meta);
    if (result == 0 && handle != 0 && mode("http-close")) {
        if (meta.len < 2 || !meta.data) exit(90);
        meta.data[0] = 42; /* CURLE_ABORTED_BY_CALLBACK: test-only cleanup failure. */
        return 3; /* GH_TRANSPORT in the explicitly pinned private HTTP ABI. */
    }
    return result;
}
