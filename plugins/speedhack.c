/// Speedhack — LD_PRELOAD library that intercepts time functions.
/// Usage: CE_SPEED=2.0 LD_PRELOAD=./libspeedhack.so ./game
/// Speed > 1.0 = faster, < 1.0 = slower

#define _GNU_SOURCE
#include <dlfcn.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

static double speed_factor = 1.0;
static struct timespec base_real_time;
static struct timespec base_fake_time;
static int initialized = 0;

// Shared memory for runtime speed control
static double* shared_speed = NULL;
static const char* SHM_NAME = "/ce_speedhack";

static void init_speedhack() {
    if (initialized) return;
    initialized = 1;

    // Get speed from environment
    const char* env = getenv("CE_SPEED");
    if (env) speed_factor = atof(env);
    if (speed_factor <= 0) speed_factor = 1.0;

    // Record base time
    clock_gettime(CLOCK_MONOTONIC, &base_real_time);
    base_fake_time = base_real_time;

    // Try to open shared memory for runtime control
    int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (fd >= 0) {
        ftruncate(fd, sizeof(double));
        shared_speed = mmap(NULL, sizeof(double), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (shared_speed != MAP_FAILED) {
            *shared_speed = speed_factor;
        } else {
            shared_speed = NULL;
        }
        close(fd);
    }

    fprintf(stderr, "[speedhack] initialized, speed=%.2f\n", speed_factor);
}

static double get_speed() {
    if (shared_speed && *shared_speed > 0)
        return *shared_speed;
    return speed_factor;
}

static void adjust_time(struct timespec* ts) {
    if (!initialized) init_speedhack();
    double spd = get_speed();

    // Calculate elapsed real time since init
    double real_elapsed = (ts->tv_sec - base_real_time.tv_sec) +
                          (ts->tv_nsec - base_real_time.tv_nsec) / 1e9;

    // Scale it
    double fake_elapsed = real_elapsed * spd;

    // Add to base fake time
    ts->tv_sec = base_fake_time.tv_sec + (long)fake_elapsed;
    ts->tv_nsec = base_fake_time.tv_nsec + (long)((fake_elapsed - (long)fake_elapsed) * 1e9);
    if (ts->tv_nsec >= 1000000000L) { ts->tv_sec++; ts->tv_nsec -= 1000000000L; }
}

// ── Intercepted functions ──

typedef int (*clock_gettime_t)(clockid_t, struct timespec*);
typedef int (*gettimeofday_t)(struct timeval*, void*);
typedef int (*nanosleep_t)(const struct timespec*, struct timespec*);

int clock_gettime(clockid_t clk_id, struct timespec* tp) {
    static clock_gettime_t real_fn = NULL;
    if (!real_fn) real_fn = (clock_gettime_t)dlsym(RTLD_NEXT, "clock_gettime");
    int ret = real_fn(clk_id, tp);
    if (ret == 0 && (clk_id == CLOCK_MONOTONIC || clk_id == CLOCK_MONOTONIC_RAW))
        adjust_time(tp);
    return ret;
}

int gettimeofday(struct timeval* tv, void* tz) {
    static gettimeofday_t real_fn = NULL;
    if (!real_fn) real_fn = (gettimeofday_t)dlsym(RTLD_NEXT, "gettimeofday");
    int ret = real_fn(tv, tz);
    if (ret == 0) {
        struct timespec ts = { tv->tv_sec, tv->tv_usec * 1000 };
        adjust_time(&ts);
        tv->tv_sec = ts.tv_sec;
        tv->tv_usec = ts.tv_nsec / 1000;
    }
    return ret;
}

int nanosleep(const struct timespec* req, struct timespec* rem) {
    static nanosleep_t real_fn = NULL;
    if (!real_fn) real_fn = (nanosleep_t)dlsym(RTLD_NEXT, "nanosleep");
    if (!initialized) init_speedhack();

    double spd = get_speed();
    if (spd <= 0) spd = 1.0;

    // Divide sleep duration by speed
    double sleep_ns = (req->tv_sec * 1e9 + req->tv_nsec) / spd;
    struct timespec adjusted = {
        .tv_sec = (time_t)(sleep_ns / 1e9),
        .tv_nsec = (long)((long long)sleep_ns % 1000000000LL)
    };
    return real_fn(&adjusted, rem);
}
