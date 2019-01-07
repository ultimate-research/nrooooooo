#ifndef LOGGING_H
#define LOGGING_H

#include "useful.h"

#include <stdint.h>

#define LOGMASK_DEBUG BIT(0)
#define LOGMASK_INFO BIT(1)
#define LOGMASK_WARN BIT(2)
#define LOGMASK_ERROR BIT(3)
#define LOGMASK_VERBOSE BIT(4)

void logmask_set(uint32_t mask);
void logmask_unset(uint32_t mask);
bool logmask_is_set(uint32_t mask);

void printf_debug(const char* format, ...);
void printf_info(const char* format, ...);
void printf_warn(const char* format, ...);
void printf_error(const char* format, ...);
void printf_verbose(const char* format, ...);

#endif // LOGGING_H
