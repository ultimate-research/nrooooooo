#ifndef UC_IMPL_H
#define UC_IMPL_H

#include <stdint.h>
#include <unicorn/unicorn.h>
#include <stdint.h>

class ClusterManager;

typedef struct uc_reg_state
{
    uint64_t x0, x1, x2, x3, x4, x5 ,x6 ,x7, x8;
    uint64_t x9, x10, x11, x12, x13, x14, x15, x16;
    uint64_t x17, x18, x19, x20, x21, x22, x23, x24;
    uint64_t x25, x26, x27, x28, fp, lr, sp, pc, nzcv;
    
    double s0, s1, s2, s3, s4, s5 ,s6 ,s7, s8;
    double s9, s10, s11, s12, s13, s14, s15, s16;
    double s17, s18, s19, s20, s21, s22, s23, s24;
    double s25, s26, s27, s28, s29, s30, s31;
} uc_reg_state;

extern void uc_read_reg_state(uc_engine *uc, struct uc_reg_state *regs);
extern void uc_write_reg_state(uc_engine *uc, struct uc_reg_state *regs);
extern void uc_print_regs(uc_engine *uc);
extern void hook_code(uc_engine *uc, uint64_t address, uint32_t size, ClusterManager* cluster);
extern void hook_import(uc_engine *uc, uint64_t address, uint32_t size, ClusterManager* cluster);
extern void hook_memrw(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, ClusterManager* cluster);
extern bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, ClusterManager* cluster);

#endif // UC_IMPL_H
