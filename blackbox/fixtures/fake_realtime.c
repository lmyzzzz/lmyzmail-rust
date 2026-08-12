#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

typedef int (*clock_gettime_fn)(clockid_t, struct timespec *);
typedef int (*gettimeofday_fn)(struct timeval *, void *);
typedef time_t (*time_fn)(time_t *);

static clock_gettime_fn real_clock_gettime;
static gettimeofday_fn real_gettimeofday;
static time_fn real_time;
static time_t realtime_offset;
static pthread_once_t initialize_once = PTHREAD_ONCE_INIT;

static void initialize(void) {
    const char *raw_target = getenv("LMYZMAIL_FAKE_REALTIME_EPOCH");
    char *end = NULL;
    long long target;
    struct timespec actual;

    real_clock_gettime = (clock_gettime_fn)dlsym(RTLD_NEXT, "clock_gettime");
    real_gettimeofday = (gettimeofday_fn)dlsym(RTLD_NEXT, "gettimeofday");
    real_time = (time_fn)dlsym(RTLD_NEXT, "time");
    if (real_clock_gettime == NULL || real_gettimeofday == NULL || real_time == NULL) {
        fputs("lmyzmail fake realtime shim could not resolve libc time functions\n", stderr);
        _Exit(127);
    }
    if (raw_target == NULL || *raw_target == '\0') {
        fputs("LMYZMAIL_FAKE_REALTIME_EPOCH is required\n", stderr);
        _Exit(127);
    }
    errno = 0;
    target = strtoll(raw_target, &end, 10);
    if (errno != 0 || end == raw_target || *end != '\0') {
        fputs("LMYZMAIL_FAKE_REALTIME_EPOCH is invalid\n", stderr);
        _Exit(127);
    }
    if (real_clock_gettime(CLOCK_REALTIME, &actual) != 0) {
        fputs("lmyzmail fake realtime shim could not read CLOCK_REALTIME\n", stderr);
        _Exit(127);
    }
    realtime_offset = (time_t)target - actual.tv_sec;
}

static void ensure_initialized(void) {
    if (pthread_once(&initialize_once, initialize) != 0) {
        fputs("lmyzmail fake realtime shim initialization failed\n", stderr);
        _Exit(127);
    }
}

int clock_gettime(clockid_t clock_id, struct timespec *value) {
    int result;
    ensure_initialized();
    result = real_clock_gettime(clock_id, value);
    if (result == 0 && clock_id == CLOCK_REALTIME) {
        value->tv_sec += realtime_offset;
    }
    return result;
}

int gettimeofday(struct timeval *value, void *timezone) {
    int result;
    ensure_initialized();
    result = real_gettimeofday(value, timezone);
    if (result == 0) {
        value->tv_sec += realtime_offset;
    }
    return result;
}

time_t time(time_t *value) {
    time_t result;
    ensure_initialized();
    result = real_time(NULL);
    if (result != (time_t)-1) {
        result += realtime_offset;
    }
    if (value != NULL) {
        *value = result;
    }
    return result;
}
