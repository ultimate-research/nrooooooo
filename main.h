#ifndef MAIN_H
#define MAIN_H

#include <unicorn/unicorn.h>
#include <vector>
#include <map>
#include "l2c.h"

extern bool trace_code;

typedef struct uc_reg_state
{
    uint64_t x0, x1, x2, x3, x4, x5 ,x6 ,x7, x8;
    uint64_t x9, x10, x11, x12, x13, x14, x15, x16;
    uint64_t x17, x18, x19, x20, x21, x22, x23, x24;
    uint64_t x25, x26, x27, x28, fp, lr, sp, pc;
} uc_reg_state;

class uc_inst;


extern int instance_id_cnt;
extern std::map<std::string, uint64_t> unresolved_syms;
extern std::map<uint64_t, std::string> unresolved_syms_rev;
extern std::map<std::string, uint64_t> resolved_syms;
extern std::map<std::pair<uint64_t, uint64_t>, uint64_t> function_hashes;
extern std::vector<L2CValue> lua_stack;
extern std::map<uint64_t, L2CValue*> lua_active_vars;

extern void nro_assignsyms(void* base);
extern void nro_relocate(void* base);
extern uint64_t hash40(const void* data, size_t len);
extern void uc_read_reg_state(uc_engine *uc, struct uc_reg_state *regs);
extern void uc_write_reg_state(uc_engine *uc, struct uc_reg_state *regs);
extern void uc_print_regs(uc_engine *uc);
extern void hook_code(uc_engine *uc, uint64_t address, uint32_t size, uc_inst* inst);
extern void hook_import(uc_engine *uc, uint64_t address, uint32_t size, uc_inst* inst);
extern void hook_memrw(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, uc_inst* inst);
extern bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, uc_inst* inst);

#endif // MAIN_H
