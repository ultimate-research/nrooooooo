#ifndef MAIN_H
#define MAIN_H

#include <unicorn/unicorn.h>
#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <unordered_set>
#include "l2c.h"

extern bool trace_code;

extern std::map<uint64_t, std::string> unhash;
extern std::map<std::string, uint64_t> unresolved_syms;
extern std::map<uint64_t, std::string> unresolved_syms_rev;
extern std::map<std::string, uint64_t> resolved_syms;
extern std::map<std::pair<uint64_t, uint64_t>, uint64_t> function_hashes;

extern void nro_assignsyms(void* base);
extern void nro_relocate(void* base);
extern uint64_t hash40(const void* data, size_t len);

#endif // MAIN_H
