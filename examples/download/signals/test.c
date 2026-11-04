/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

int64_t gd_signals_start(void);
int64_t gd_signals_received(void);
int64_t gd_signals_stop(void);
int __real_sigaction(int, const struct sigaction *, struct sigaction *);

static int action_calls;
static int failures[8];
static volatile sig_atomic_t previous_int_calls, previous_term_calls;

int __wrap_sigaction(int number, const struct sigaction *action, struct sigaction *previous) {
    ++action_calls;
    if (action_calls < (int)(sizeof failures / sizeof failures[0]) && failures[action_calls]) {
        errno = failures[action_calls];
        return -1;
    }
    return __real_sigaction(number, action, previous);
}
static void previous_handler(int number) {
    if (number == SIGINT) ++previous_int_calls;
    else if (number == SIGTERM) ++previous_term_calls;
}
static void reset_faults(void) {
    action_calls = 0;
    for (size_t i = 0; i < sizeof failures / sizeof failures[0]; ++i) failures[i] = 0;
}
static void install_previous_handlers(void) {
    struct sigaction action = {0};
    action.sa_handler = previous_handler;
    action.sa_flags = SA_RESTART;
    assert(sigemptyset(&action.sa_mask) == 0);
    assert(sigaddset(&action.sa_mask, SIGUSR1) == 0);
    assert(__real_sigaction(SIGINT, &action, NULL) == 0);
    assert(__real_sigaction(SIGTERM, &action, NULL) == 0);
    previous_int_calls = previous_term_calls = 0;
}
static void assert_previous_action(int number) {
    struct sigaction actual;
    assert(__real_sigaction(number, NULL, &actual) == 0);
    assert(actual.sa_handler == previous_handler);
    assert((actual.sa_flags & SA_RESTART) != 0);
    assert(sigismember(&actual.sa_mask, SIGUSR1) == 1);
}
static void assert_restored(void) {
    assert_previous_action(SIGINT);
    assert_previous_action(SIGTERM);
}
static void lifecycle(void) {
    reset_faults(); install_previous_handlers();
    assert(gd_signals_received() == 0);
    assert(gd_signals_start() == 0 && action_calls == 2);
    assert(gd_signals_received() == 0);
    assert(raise(SIGINT) == 0 && gd_signals_received() == SIGINT);
    assert(!previous_int_calls && !previous_term_calls);
    assert(gd_signals_start() == EALREADY && action_calls == 2);
    assert(gd_signals_received() == SIGINT); /* Rejected start must not clear cancellation. */
    for (int i = 0; i < 32; ++i) {
        int number = i % 2 ? SIGINT : SIGTERM;
        assert(raise(number) == 0 && gd_signals_received() == number);
    }
    assert(action_calls == 2); /* Signals update the flag, never perform cleanup. */
    assert(!previous_int_calls && !previous_term_calls);
    assert(gd_signals_stop() == 0 && action_calls == 4);
    assert(gd_signals_stop() == 0 && action_calls == 4);
    assert_restored();
    assert(raise(SIGINT) == 0 && previous_int_calls == 1);
    assert(raise(SIGTERM) == 0 && previous_term_calls == 1);
    assert(gd_signals_start() == 0 && gd_signals_received() == 0);
    assert(gd_signals_stop() == 0);
    assert_restored();
}
static void installation_failures(void) {
    for (int at = 1; at <= 2; ++at) {
        reset_faults(); install_previous_handlers(); failures[at] = EIO;
        assert(gd_signals_start() == EIO && action_calls == at);
        if (at == 1) {
            assert_restored();
            assert(raise(SIGINT) == 0 && previous_int_calls == 1);
        } else {
            assert(raise(SIGINT) == 0 && gd_signals_received() == SIGINT);
            assert(!previous_int_calls);
            assert(raise(SIGTERM) == 0 && previous_term_calls == 1);
            assert(gd_signals_start() == EALREADY && action_calls == 2);
        }
        assert(gd_signals_stop() == 0);
        assert(action_calls == (at == 1 ? 1 : 3));
        assert_restored();
        reset_faults();
        assert(gd_signals_start() == 0 && gd_signals_received() == 0);
        assert(gd_signals_stop() == 0);
        assert_restored();
    }
}
static void restoration_failures(void) {
    for (int at = 1; at <= 2; ++at) {
        reset_faults(); install_previous_handlers();
        assert(gd_signals_start() == 0);
        reset_faults(); failures[at] = EINTR;
        assert(gd_signals_stop() == EINTR && action_calls == 2);
        assert(gd_signals_start() == EALREADY && action_calls == 2);
        /* One failed restoration remains tracked; the other is already restored. */
        assert(raise(SIGINT) == 0);
        assert(raise(SIGTERM) == 0);
        assert(previous_int_calls == (at == 1 ? 0 : 1));
        assert(previous_term_calls == (at == 2 ? 0 : 1));
        assert(gd_signals_received() == (at == 1 ? SIGINT : SIGTERM));
        reset_faults();
        assert(gd_signals_stop() == 0 && action_calls == 1);
        assert(gd_signals_stop() == 0 && action_calls == 1);
        assert_restored();
    }
    reset_faults(); install_previous_handlers();
    assert(gd_signals_start() == 0);
    reset_faults(); failures[1] = EINTR; failures[2] = EACCES;
    assert(gd_signals_stop() == EINTR && action_calls == 2); /* First error wins. */
    assert(gd_signals_start() == EALREADY);
    assert(raise(SIGTERM) == 0 && gd_signals_received() == SIGTERM);
    assert(!previous_int_calls && !previous_term_calls);
    reset_faults();
    assert(gd_signals_stop() == 0 && action_calls == 2);
    assert_restored();
    assert(gd_signals_start() == 0 && gd_signals_received() == 0);
    assert(gd_signals_stop() == 0);
}
int main(void) {
    lifecycle(); installation_failures(); restoration_failures();
    puts("download signal guard: lifecycle, repeated signals, prior actions and partial failures passed");
    return 0;
}
