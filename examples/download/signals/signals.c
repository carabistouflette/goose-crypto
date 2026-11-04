/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>

#if ATOMIC_INT_LOCK_FREE != 2
#error "download signal flag requires always-lock-free atomic int"
#endif
static atomic_int received_signal;
static struct sigaction previous_int, previous_term;
static int installed_int, installed_term;

/* No allocation, I/O, Goose callback or resource cleanup in a signal handler. */
static void receive_signal(int number) {
    atomic_store_explicit(&received_signal, number, memory_order_relaxed);
}
int64_t gd_signals_start(void) {
    if (installed_int || installed_term) return EALREADY;
    atomic_store_explicit(&received_signal, 0, memory_order_relaxed);
    struct sigaction action = {0};
    action.sa_handler = receive_signal;
    if (sigemptyset(&action.sa_mask)) return errno;
    if (sigaction(SIGINT, &action, &previous_int)) return errno;
    installed_int = 1;
    /* Partial setup remains tracked: the caller must invoke stop on failure. */
    if (sigaction(SIGTERM, &action, &previous_term)) return errno;
    installed_term = 1;
    return 0;
}
int64_t gd_signals_received(void) {
    return atomic_load_explicit(&received_signal, memory_order_relaxed);
}
int64_t gd_signals_stop(void) {
    int failure = 0;
    if (installed_int) {
        if (sigaction(SIGINT, &previous_int, NULL)) failure = errno;
        else installed_int = 0;
    }
    if (installed_term) {
        if (sigaction(SIGTERM, &previous_term, NULL)) {
            if (!failure) failure = errno;
        } else installed_term = 0;
    }
    return failure;
}
