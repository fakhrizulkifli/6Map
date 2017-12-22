#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "logger.h"
#include <unistd.h>

/*
 * thanks masscan :)
 */

static int global_debug_level = 0;

void
LOG_add_level(int x)
{
    global_debug_level += x;
}

static void
vLOG(int level, const char *fmt, va_list marker)
{
    if (level <= global_debug_level)
    {
        vfprintf(stderr, fmt, marker);
        fflush(stderr);
    }
}

void
LOG(int level, const char *fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    vLOG(level, fmt, marker);
    va_end(marker);
}

void
DEBUG(const char *fmt, ...)
{
    va_list marker;
    va_start(marker, fmt);
    vfprintf(stderr, fmt, marker);
    va_end(marker);
}
