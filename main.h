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

typedef struct uc_reg_state
{
    uint64_t x0, x1, x2, x3, x4, x5 ,x6 ,x7, x8;
    uint64_t x9, x10, x11, x12, x13, x14, x15, x16;
    uint64_t x17, x18, x19, x20, x21, x22, x23, x24;
    uint64_t x25, x26, x27, x28, fp, lr, sp, pc;
    
    double s0, s1, s2, s3, s4, s5 ,s6 ,s7, s8;
    double s9, s10, s11, s12, s13, s14, s15, s16;
    double s17, s18, s19, s20, s21, s22, s23, s24;
    double s25, s26, s27, s28, s29, s30, s31;
} uc_reg_state;

class uc_inst;

extern int instance_id_cnt;
extern std::map<std::string, uint64_t> unresolved_syms;
extern std::map<uint64_t, std::string> unresolved_syms_rev;
extern std::map<std::string, uint64_t> resolved_syms;
extern std::map<std::pair<uint64_t, uint64_t>, uint64_t> function_hashes;
extern std::map<uint64_t, std::set<L2C_Token> > tokens;
extern std::map<uint64_t, bool> converge_points;
extern std::map<uint64_t, L2C_CodeBlock> blocks;

extern std::map<uint64_t, bool> is_goto_dst;
extern std::map<uint64_t, bool> is_fork_origin;

extern void add_token_by_prio(uc_inst* inst, uint64_t block, L2C_Token token);
extern void remove_matching_tokens(uint64_t addr, std::string str);
extern void remove_block_matching_tokens(uint64_t block, uint64_t addr, std::string str);
extern bool token_by_addr_and_name_exists(uint64_t pc, std::string str);
extern uint64_t find_containing_block(uint64_t addr);
extern void invalidate_blocktree(uc_inst* inst, uint64_t func);
extern void clean_and_verify_blocks(uint64_t func);

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
