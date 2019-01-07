#include "logging.h"

#include <stdio.h>
#include <stdarg.h>

static uint32_t logmask = LOGMASK_DEBUG | LOGMASK_INFO | LOGMASK_WARN | LOGMASK_ERROR;

void logmask_set(uint32_t mask)
{
    logmask |= mask;
}

void logmask_unset(uint32_t mask)
{
    logmask &= ~mask;
}

bool logmask_is_set(uint32_t mask)
{
    return logmask & mask;
}

void printf_debug(const char* format, ...)
{
    va_list argptr;
    
    if (~logmask & LOGMASK_DEBUG)
        return;
    
    printf("[DEBUG] ");
    
    va_start(argptr, format);
    vprintf(format, argptr);
    va_end(argptr);
}

void printf_info(const char* format, ...)
{
    va_list argptr;
    
    if (~logmask & LOGMASK_INFO)
        return;
    
    printf("[INFO] ");
    
    va_start(argptr, format);
    vprintf(format, argptr);
    va_end(argptr);
}

void printf_warn(const char* format, ...)
{
    va_list argptr;
    
    if (~logmask & LOGMASK_WARN)
        return;
    
    printf("[WARN] ");
    
    va_start(argptr, format);
    vprintf(format, argptr);
    va_end(argptr);
}

void printf_error(const char* format, ...)
{
    va_list argptr;
    
    if (~logmask & LOGMASK_ERROR)
        return;
    
    printf("[ERROR] ");
    
    va_start(argptr, format);
    vprintf(format, argptr);
    va_end(argptr);
}

void printf_verbose(const char* format, ...)
{
    va_list argptr;
    
    if (~logmask & LOGMASK_VERBOSE)
        return;
    
    printf("[VERBOSE] ");
    
    va_start(argptr, format);
    vprintf(format, argptr);
    va_end(argptr);
}
