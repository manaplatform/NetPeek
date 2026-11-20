/*****************************************************************************
 * npe_lib_time.c — NPE Time Library Implementation
 *
 * Timing, delays, and elapsed measurement for NPE scripts.
 * Thread-safe, sandbox-safe. See npe_lib_time.h for full documentation.
 *
 *****************************************************************************/

/* Feature-test macros must be defined before ANY system header is included:
 * npe_lib_time.h already pulls in <time.h>, and under strict C11 glibc only
 * declares strptime() when _XOPEN_SOURCE >= 500. Defining these after the
 * includes (as this file used to) is a no-op and caused the Release CI build
 * to fail with "implicit declaration of function strptime".
 * _DEFAULT_SOURCE keeps timegm() visible on glibc; _DARWIN_C_SOURCE (set by
 * CMake) keeps the Darwin extensions enabled alongside _XOPEN_SOURCE. */
#ifndef _WIN32
  #ifndef _XOPEN_SOURCE
    #define _XOPEN_SOURCE 700
  #endif
  #ifndef _DEFAULT_SOURCE
    #define _DEFAULT_SOURCE 1
  #endif
#endif

#include "npe_lib_time.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <errno.h>
#include <float.h>

/* ---------------------------------------------------------------------------
 * Platform-specific includes
 * --------------------------------------------------------------------------- */

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
#else
  #include <unistd.h>
  #include <sys/time.h>
#endif

/* =============================================================================
 * INTERNAL HELPERS
 * ============================================================================= */

/**
 * Normalise a timespec-like stamp so that nsec is in [0, 999999999].
 */
static void stamp_normalise(npe_time_stamp_t *ts) {
    while (ts->nsec >= 1000000000LL) {
        ts->sec  += 1;
        ts->nsec -= 1000000000LL;
    }
    while (ts->nsec < 0) {
        ts->sec  -= 1;
        ts->nsec += 1000000000LL;
    }
}

/**
 * Convert a npe_time_stamp_t to a double (seconds with fractional part).
 */
static double stamp_to_double(const npe_time_stamp_t *ts) {
    return (double)ts->sec + (double)ts->nsec / 1e9;
}

/**
 * Convert a double (seconds) to a npe_time_stamp_t.
 */
static npe_time_stamp_t double_to_stamp(double s) {
    npe_time_stamp_t ts;
    ts.sec  = (int64_t)s;
    ts.nsec = (int64_t)((s - (double)ts.sec) * 1e9);
    stamp_normalise(&ts);
    return ts;
}

/**
 * Clamp a double to [0, NPE_TIME_MAX_SLEEP_SEC].
 */
static double clamp_sleep_sec(double s) {
    if (s != s) return 0.0;                         /* NaN guard */
    if (s < 0.0) return 0.0;
    if (s > (double)NPE_TIME_MAX_SLEEP_SEC) return (double)NPE_TIME_MAX_SLEEP_SEC;
    return s;
}

/**
 * Clamp an int64 to [0, NPE_TIME_MAX_SLEEP_MS].
 */
static int64_t clamp_sleep_ms(int64_t ms) {
    if (ms < 0) return 0;
    if (ms > (int64_t)NPE_TIME_MAX_SLEEP_MS) return (int64_t)NPE_TIME_MAX_SLEEP_MS;
    return ms;
}


/* =============================================================================
 * PLATFORM CLOCK BACKENDS
 * ============================================================================= */

#ifdef _WIN32

/* ---- Windows implementation ---- */

/* Frequency of the performance counter (cached at first call) */
static LARGE_INTEGER qpc_freq = { .QuadPart = 0 };

static void win_init_qpc(void) {
    if (qpc_freq.QuadPart == 0) {
        QueryPerformanceFrequency(&qpc_freq);
    }
}

npe_time_error_t npe_time_monotonic_now(npe_time_stamp_t *ts) {
    if (!ts) return NPE_TIME_ERR_INVALID_ARG;

    win_init_qpc();

    LARGE_INTEGER counter;
    if (!QueryPerformanceCounter(&counter))
        return NPE_TIME_ERR_CLOCK_FAIL;

    ts->sec  = (int64_t)(counter.QuadPart / qpc_freq.QuadPart);
    ts->nsec = (int64_t)(((counter.QuadPart % qpc_freq.QuadPart) * 1000000000LL)
                         / qpc_freq.QuadPart);
    stamp_normalise(ts);
    return NPE_TIME_OK;
}

npe_time_error_t npe_time_realtime_now(npe_time_stamp_t *ts) {
    if (!ts) return NPE_TIME_ERR_INVALID_ARG;

    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);

    /* FILETIME is 100-ns intervals since 1601-01-01.
     * UNIX epoch offset: 11644473600 seconds. */
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    uint64_t unix_100ns = t - 116444736000000000ULL;

    ts->sec  = (int64_t)(unix_100ns / 10000000ULL);
    ts->nsec = (int64_t)((unix_100ns % 10000000ULL) * 100LL);
    stamp_normalise(ts);
    return NPE_TIME_OK;
}

npe_time_error_t npe_time_sleep_sec(double seconds) {
    seconds = clamp_sleep_sec(seconds);
    if (seconds < (double)NPE_TIME_MIN_SLEEP_MS / 1000.0)
        return NPE_TIME_OK;

    DWORD ms = (DWORD)(seconds * 1000.0);
    if (ms < 1) ms = 1;
    Sleep(ms);
    return NPE_TIME_OK;
}

npe_time_error_t npe_time_sleep_msec(int64_t ms) {
    ms = clamp_sleep_ms(ms);
    if (ms < NPE_TIME_MIN_SLEEP_MS)
        return NPE_TIME_OK;

    Sleep((DWORD)ms);
    return NPE_TIME_OK;
}

/* Windows lacks strptime — provide a minimal implementation */
static char *win_strptime(const char *str, const char *fmt, struct tm *tm) {
    /* Minimal: support %Y-%m-%d %H:%M:%S only via sscanf fallback */
    memset(tm, 0, sizeof(*tm));

    /* Try the most common format first */
    int n = sscanf(str, "%d-%d-%d %d:%d:%d",
                   &tm->tm_year, &tm->tm_mon, &tm->tm_mday,
                   &tm->tm_hour, &tm->tm_min, &tm->tm_sec);
    if (n >= 3) {
        tm->tm_year -= 1900;
        tm->tm_mon  -= 1;
        /* advance past consumed characters (approximate) */
        const char *p = str;
        while (*p) p++;
        return (char *)p;
    }
    return NULL;
}

#else

/* ---- POSIX implementation ---- */

npe_time_error_t npe_time_monotonic_now(npe_time_stamp_t *ts) {
    if (!ts) return NPE_TIME_ERR_INVALID_ARG;

    struct timespec tp;
    if (clock_gettime(NPE_TIME_CLOCK_SOURCE, &tp) != 0)
        return NPE_TIME_ERR_CLOCK_FAIL;

    ts->sec  = (int64_t)tp.tv_sec;
    ts->nsec = (int64_t)tp.tv_nsec;
    return NPE_TIME_OK;
}

npe_time_error_t npe_time_realtime_now(npe_time_stamp_t *ts) {
    if (!ts) return NPE_TIME_ERR_INVALID_ARG;

    struct timespec tp;
    if (clock_gettime(CLOCK_REALTIME, &tp) != 0)
        return NPE_TIME_ERR_CLOCK_FAIL;

    ts->sec  = (int64_t)tp.tv_sec;
    ts->nsec = (int64_t)tp.tv_nsec;
    return NPE_TIME_OK;
}

npe_time_error_t npe_time_sleep_sec(double seconds) {
    seconds = clamp_sleep_sec(seconds);
    if (seconds < (double)NPE_TIME_MIN_SLEEP_MS / 1000.0)
        return NPE_TIME_OK;

    npe_time_stamp_t dur = double_to_stamp(seconds);
    struct timespec req, rem;
    req.tv_sec  = (time_t)dur.sec;
    req.tv_nsec = (long)dur.nsec;

    /* restart on EINTR */
    while (nanosleep(&req, &rem) != 0) {
        if (errno == EINTR) {
            req = rem;
        } else {
            return NPE_TIME_ERR_SLEEP_FAIL;
        }
    }
    return NPE_TIME_OK;
}

npe_time_error_t npe_time_sleep_msec(int64_t ms) {
    ms = clamp_sleep_ms(ms);
    if (ms < NPE_TIME_MIN_SLEEP_MS)
        return NPE_TIME_OK;

    double seconds = (double)ms / 1000.0;
    return npe_time_sleep_sec(seconds);
}

#endif /* _WIN32 */


/* =============================================================================
 * PLATFORM-INDEPENDENT C UTILITY FUNCTIONS
 * ============================================================================= */

double npe_time_elapsed_sec(const npe_time_stamp_t *start,
                            const npe_time_stamp_t *end)
{
    if (!start || !end) return 0.0;

    double s = stamp_to_double(end) - stamp_to_double(start);
    return (s > 0.0) ? s : 0.0;
}

int64_t npe_time_elapsed_ms(const npe_time_stamp_t *start,
                            const npe_time_stamp_t *end)
{
    if (!start || !end) return 0;

    int64_t dsec  = end->sec  - start->sec;
    int64_t dnsec = end->nsec - start->nsec;

    int64_t ms = dsec * 1000LL + dnsec / 1000000LL;
    return (ms > 0) ? ms : 0;
}

npe_time_error_t npe_time_format(double ts, const char *fmt,
                                 char *buf, size_t buflen)
{
    if (!fmt || !buf || buflen == 0)
        return NPE_TIME_ERR_INVALID_ARG;

    if (strlen(fmt) > NPE_TIME_MAX_FMT_LEN)
        return NPE_TIME_ERR_INVALID_ARG;

    time_t epoch = (time_t)ts;
    struct tm tm_result;

#ifdef _WIN32
    if (gmtime_s(&tm_result, &epoch) != 0)
        return NPE_TIME_ERR_FORMAT_FAIL;
#else
    if (gmtime_r(&epoch, &tm_result) == NULL)
        return NPE_TIME_ERR_FORMAT_FAIL;
#endif

    size_t written = strftime(buf, buflen, fmt, &tm_result);
    if (written == 0)
        return NPE_TIME_ERR_FORMAT_FAIL;

    return NPE_TIME_OK;
}

npe_time_error_t npe_time_parse(const char *str, const char *fmt, double *ts) {
    if (!str || !fmt || !ts)
        return NPE_TIME_ERR_INVALID_ARG;

    if (strlen(fmt) > NPE_TIME_MAX_FMT_LEN)
        return NPE_TIME_ERR_INVALID_ARG;

    struct tm tm_result;
    memset(&tm_result, 0, sizeof(tm_result));

#ifdef _WIN32
    char *ret = win_strptime(str, fmt, &tm_result);
#else
    char *ret = strptime(str, fmt, &tm_result);
#endif

    if (ret == NULL)
        return NPE_TIME_ERR_PARSE_FAIL;

    /* Use timegm (POSIX) or _mkgmtime (Windows) for UTC conversion */
#ifdef _WIN32
    time_t epoch = _mkgmtime(&tm_result);
#else
    time_t epoch = timegm(&tm_result);
#endif

    if (epoch == (time_t)-1)
        return NPE_TIME_ERR_PARSE_FAIL;

    *ts = (double)epoch;
    return NPE_TIME_OK;
}

const char *npe_time_strerror(npe_time_error_t err) {
    switch (err) {
        case NPE_TIME_OK:               return "success";
        case NPE_TIME_ERR_INVALID_ARG:  return "invalid argument";
        case NPE_TIME_ERR_CLOCK_FAIL:   return "clock read failed";
        case NPE_TIME_ERR_SLEEP_FAIL:   return "sleep failed";
        case NPE_TIME_ERR_FORMAT_FAIL:  return "time format failed";
        case NPE_TIME_ERR_PARSE_FAIL:   return "time parse failed";
        case NPE_TIME_ERR_OVERFLOW:     return "value overflow";
        default:                         return "unknown time error";
    }
}


/* =============================================================================
 * LUA-FACING API FUNCTIONS
 * ============================================================================= */

/* ---------- time.now() -> number ---------------------------------------- */

int npe_lua_time_now(lua_State *L) {
    npe_time_stamp_t ts;
    npe_time_error_t err = npe_time_realtime_now(&ts);

    if (err != NPE_TIME_OK) {
        lua_pushnil(L);
        lua_pushstring(L, npe_time_strerror(err));
        return 2;
    }

    lua_pushnumber(L, stamp_to_double(&ts));
    return 1;
}

/* ---------- time.now_ms() -> integer ------------------------------------ */

int npe_lua_time_now_ms(lua_State *L) {
    npe_time_stamp_t ts;
    npe_time_error_t err = npe_time_realtime_now(&ts);

    if (err != NPE_TIME_OK) {
        lua_pushnil(L);
        lua_pushstring(L, npe_time_strerror(err));
        return 2;
    }

    int64_t ms = ts.sec * 1000LL + ts.nsec / 1000000LL;
    lua_pushinteger(L, (lua_Integer)ms);
    return 1;
}

/* ---------- time.sleep(seconds) -> nil ---------------------------------- */

int npe_lua_time_sleep(lua_State *L) {
    double seconds = luaL_checknumber(L, 1);

    npe_time_error_t err = npe_time_sleep_sec(seconds);

    if (err != NPE_TIME_OK) {
        lua_pushnil(L);
        lua_pushstring(L, npe_time_strerror(err));
        return 2;
    }

    return 0;
}

/* ---------- time.sleep_ms(ms) -> nil ------------------------------------ */

int npe_lua_time_sleep_ms(lua_State *L) {
    lua_Integer ms = luaL_checkinteger(L, 1);

    npe_time_error_t err = npe_time_sleep_msec((int64_t)ms);

    if (err != NPE_TIME_OK) {
        lua_pushnil(L);
        lua_pushstring(L, npe_time_strerror(err));
        return 2;
    }

    return 0;
}

/* ---------- time.elapsed(start) -> number ------------------------------- */

int npe_lua_time_elapsed(lua_State *L) {
    double start_ts = luaL_checknumber(L, 1);

    npe_time_stamp_t now;
    npe_time_error_t err = npe_time_realtime_now(&now);

    if (err != NPE_TIME_OK) {
        lua_pushnil(L);
        lua_pushstring(L, npe_time_strerror(err));
        return 2;
    }

    double now_d = stamp_to_double(&now);
    double elapsed = now_d - start_ts;

    lua_pushnumber(L, (elapsed > 0.0) ? elapsed : 0.0);
    return 1;
}

/* ---------- time.monotonic() -> number ---------------------------------- */

int npe_lua_time_monotonic(lua_State *L) {
    npe_time_stamp_t ts;
    npe_time_error_t err = npe_time_monotonic_now(&ts);

    if (err != NPE_TIME_OK) {
        lua_pushnil(L);
        lua_pushstring(L, npe_time_strerror(err));
        return 2;
    }

    lua_pushnumber(L, stamp_to_double(&ts));
    return 1;
}

/* ---------- time.format(ts, fmt) -> string | nil, errmsg ---------------- */

int npe_lua_time_format(lua_State *L) {
    double ts       = luaL_checknumber(L, 1);
    const char *fmt = luaL_checkstring(L, 2);

    char buf[NPE_TIME_MAX_FMT_OUTPUT];
    npe_time_error_t err = npe_time_format(ts, fmt, buf, sizeof(buf));

    if (err != NPE_TIME_OK) {
        lua_pushnil(L);
        lua_pushstring(L, npe_time_strerror(err));
        return 2;
    }

    lua_pushstring(L, buf);
    return 1;
}

/* ---------- time.parse(str, fmt) -> number | nil, errmsg ---------------- */

int npe_lua_time_parse(lua_State *L) {
    const char *str = luaL_checkstring(L, 1);
    const char *fmt = luaL_checkstring(L, 2);

    double ts = 0.0;
    npe_time_error_t err = npe_time_parse(str, fmt, &ts);

    if (err != NPE_TIME_OK) {
        lua_pushnil(L);
        lua_pushstring(L, npe_time_strerror(err));
        return 2;
    }

    lua_pushnumber(L, ts);
    return 1;
}


/* =============================================================================
 * LIBRARY REGISTRATION
 * ============================================================================= */

const luaL_Reg npe_lib_time_funcs[] = {
    { "now",        npe_lua_time_now        },
    { "now_ms",     npe_lua_time_now_ms     },
    { "sleep",      npe_lua_time_sleep      },
    { "sleep_ms",   npe_lua_time_sleep_ms   },
    { "elapsed",    npe_lua_time_elapsed    },
    { "monotonic",  npe_lua_time_monotonic  },
    { "format",     npe_lua_time_format     },
    { "parse",      npe_lua_time_parse      },
    { NULL,         NULL                    }
};

int npe_lib_time_register(lua_State *L) {
    if (!L) return 0;

#if LUA_VERSION_NUM >= 502
    /* Lua 5.2+ */
    luaL_newlib(L, npe_lib_time_funcs);
#else
    /* Lua 5.1 */
    luaL_register(L, "time", npe_lib_time_funcs);
#endif

    /* Also set as global "time" for convenience */
    lua_setglobal(L, "time");

    /* Push the table back on the stack as the return value */
    lua_getglobal(L, "time");

    /* Embed constants into the table for introspection from Lua */
    lua_pushinteger(L, NPE_TIME_MAX_SLEEP_SEC);
    lua_setfield(L, -2, "MAX_SLEEP_SEC");

    lua_pushinteger(L, NPE_TIME_MAX_SLEEP_MS);
    lua_setfield(L, -2, "MAX_SLEEP_MS");

    lua_pushinteger(L, NPE_TIME_MIN_SLEEP_MS);
    lua_setfield(L, -2, "MIN_SLEEP_MS");

    lua_pushinteger(L, NPE_TIME_MAX_FMT_LEN);
    lua_setfield(L, -2, "MAX_FMT_LEN");

    lua_pushinteger(L, NPE_TIME_MAX_FMT_OUTPUT);
    lua_setfield(L, -2, "MAX_FMT_OUTPUT");

    return 1;
}
