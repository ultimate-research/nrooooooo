#include "main.h"

#include <string.h>
#include <time.h>
#include <iostream>
#include <filesystem>
#include <list>
#include <algorithm>
#include <elf.h>
#include <cxxabi.h>
#include "crc32.h"
#include "uc_inst.h"
#include "logging.h"
#include "eh.h"

int instance_id_cnt = 0;
int imports_size = 0;
std::map<std::string, uint64_t> unresolved_syms;
std::map<uint64_t, std::string> unresolved_syms_rev;
std::map<std::string, uint64_t> resolved_syms;
std::map<std::pair<uint64_t, uint64_t>, uint64_t> function_hashes;
std::map<uint64_t, std::set<L2C_Token> > tokens;
std::map<uint64_t, bool> converge_points;
std::map<uint64_t, L2C_CodeBlock> blocks;

std::map<uint64_t, bool> is_goto_dst;
std::map<uint64_t, bool> is_fork_origin;

std::map<uint64_t, uint64_t> hash_cheat;
std::map<uint64_t, uint64_t> hash_cheat_rev;
uint64_t hash_cheat_ptr;

bool syms_scanned = false;
bool trace_code = true;

struct nso_header
{
    uint32_t start;
    uint32_t mod;
};

struct mod0_header
{
    uint32_t magic;
    int32_t dynamic;
    int32_t bss_start;
    int32_t bss_end;
    int32_t unwind_start;
    int32_t unwind_end;
};

void nro_assignsyms(void* base)
{
    const Elf64_Dyn* dyn = NULL;
    const Elf64_Sym* symtab = NULL;
    const char* strtab = NULL;
    uint64_t numsyms = 0;
    
    if (syms_scanned) return;
    
    struct nso_header* header = (struct nso_header*)base;
    struct mod0_header* modheader = (struct mod0_header*)(base + header->mod);
    dyn = (const Elf64_Dyn*)((void*)modheader + modheader->dynamic);
    
    //parse_eh(base, header->mod + modheader->unwind_start);
    
    for (; dyn->d_tag != DT_NULL; dyn++)
    {
        switch (dyn->d_tag)
        {
            case DT_SYMTAB:
                symtab = (const Elf64_Sym*)(base + dyn->d_un.d_ptr);
                break;
            case DT_STRTAB:
                strtab = (const char*)(base + dyn->d_un.d_ptr);
                break;
        }
    }
    
    numsyms = ((uintptr_t)strtab - (uintptr_t)symtab) / sizeof(Elf64_Sym);
    
    for (uint64_t i = 0; i < numsyms; i++)
    {
        char* demangled = abi::__cxa_demangle(strtab + symtab[i].st_name, 0, 0, 0);

        if (symtab[i].st_shndx == 0 && demangled)
        {
            //TODO: just read the main NSO for types/sizes? Or have them resolve to the main NSO

            uint64_t import_size = 0x8;
            std::string demangled_str = std::string(demangled);
            if (demangled_str == "phx::detail::CRC32Table::table_")
            {
                import_size = 0x100;
            }
            else if (demangled_str == "lib::L2CValue::NIL")
            {
                import_size = 0x10;
            }
            else if (!strncmp(demangled, "`vtable for'", 12))
            {
                import_size = 0x1000;
            }
            
            uint64_t addr = IMPORTS + (imports_size + import_size);
            unresolved_syms[std::string(demangled_str)] = addr;
            unresolved_syms_rev[addr] = std::string(demangled);
            
            imports_size += import_size;
        }
        else if (symtab[i].st_shndx && demangled)
        {
            resolved_syms[std::string(demangled)] = NRO + symtab[i].st_value;
        }
        free(demangled);
    }
    
    syms_scanned = true;
}

void nro_relocate(void* base)
{
    const Elf64_Dyn* dyn = NULL;
    const Elf64_Rela* rela = NULL;
    const Elf64_Sym* symtab = NULL;
    const char* strtab = NULL;
    uint64_t relasz = 0;
    uint64_t numsyms = 0;
    
    struct nso_header* header = (struct nso_header*)base;
    struct mod0_header* modheader = (struct mod0_header*)(base + header->mod);
    dyn = (const Elf64_Dyn*)((void*)modheader + modheader->dynamic);

    for (; dyn->d_tag != DT_NULL; dyn++)
    {
        switch (dyn->d_tag)
        {
            case DT_SYMTAB:
                symtab = (const Elf64_Sym*)(base + dyn->d_un.d_ptr);
                break;
            case DT_STRTAB:
                strtab = (const char*)(base + dyn->d_un.d_ptr);
                break;
            case DT_RELA:
                rela = (const Elf64_Rela*)(base + dyn->d_un.d_ptr);
                break;
            case DT_RELASZ:
                relasz = dyn->d_un.d_val / sizeof(Elf64_Rela);
                break;
            case DT_PLTRELSZ:
                relasz += dyn->d_un.d_val / sizeof(Elf64_Rela);
                break;
        }
    }
    
    if (rela == NULL)
    {
        return;
    }

    for (; relasz--; rela++)
    {
        uint32_t sym_idx = ELF64_R_SYM(rela->r_info);
        const char* name = strtab + symtab[sym_idx].st_name;

        uint64_t sym_val = (uint64_t)base + symtab[sym_idx].st_value;
        if (!symtab[sym_idx].st_value)
            sym_val = 0;

        switch (ELF64_R_TYPE(rela->r_info))
        {
            case R_AARCH64_RELATIVE:
            {
                uint64_t* ptr = (uint64_t*)(base + rela->r_offset);
                *ptr = NRO + rela->r_addend;
                break;
            }
            case R_AARCH64_GLOB_DAT:
            case R_AARCH64_JUMP_SLOT:
            case R_AARCH64_ABS64:
            {
                uint64_t* ptr = (uint64_t*)(base + rela->r_offset);
                char* demangled = abi::__cxa_demangle(name, 0, 0, 0);
                
                if (demangled)
                {
                    //printf("@ %" PRIx64 ", %s -> %" PRIx64 ", %" PRIx64 "\n", NRO + rela->r_offset, demangled, unresolved_syms[std::string(demangled)], *ptr);
                    *ptr = unresolved_syms[std::string(demangled)];
                    free(demangled);
                }
                break;
            }
            default:
            {
                printf("Unknown relocation type %" PRId32 "\n", ELF64_R_TYPE(rela->r_info));
                break;
            }
        }
    }
}

uint64_t hash40(const void* data, size_t len)
{
    return crc32(data, len) | (len & 0xFF) << 32;
}

void uc_read_reg_state(uc_engine *uc, struct uc_reg_state *regs)
{
    uc_reg_read(uc, UC_ARM64_REG_X0, &regs->x0);
    uc_reg_read(uc, UC_ARM64_REG_X1, &regs->x1);
    uc_reg_read(uc, UC_ARM64_REG_X2, &regs->x2);
    uc_reg_read(uc, UC_ARM64_REG_X3, &regs->x3);
    uc_reg_read(uc, UC_ARM64_REG_X4, &regs->x4);
    uc_reg_read(uc, UC_ARM64_REG_X5, &regs->x5);
    uc_reg_read(uc, UC_ARM64_REG_X6, &regs->x6);
    uc_reg_read(uc, UC_ARM64_REG_X7, &regs->x7);
    uc_reg_read(uc, UC_ARM64_REG_X8, &regs->x8);
    uc_reg_read(uc, UC_ARM64_REG_X9, &regs->x9);
    uc_reg_read(uc, UC_ARM64_REG_X10, &regs->x10);
    uc_reg_read(uc, UC_ARM64_REG_X11, &regs->x11);
    uc_reg_read(uc, UC_ARM64_REG_X12, &regs->x12);
    uc_reg_read(uc, UC_ARM64_REG_X13, &regs->x13);
    uc_reg_read(uc, UC_ARM64_REG_X14, &regs->x14);
    uc_reg_read(uc, UC_ARM64_REG_X15, &regs->x15);
    uc_reg_read(uc, UC_ARM64_REG_X16, &regs->x16);
    uc_reg_read(uc, UC_ARM64_REG_X17, &regs->x17);
    uc_reg_read(uc, UC_ARM64_REG_X18, &regs->x18);
    uc_reg_read(uc, UC_ARM64_REG_X19, &regs->x19);
    uc_reg_read(uc, UC_ARM64_REG_X20, &regs->x20);
    uc_reg_read(uc, UC_ARM64_REG_X21, &regs->x21);
    uc_reg_read(uc, UC_ARM64_REG_X22, &regs->x22);
    uc_reg_read(uc, UC_ARM64_REG_X23, &regs->x23);
    uc_reg_read(uc, UC_ARM64_REG_X24, &regs->x24);
    uc_reg_read(uc, UC_ARM64_REG_X25, &regs->x25);
    uc_reg_read(uc, UC_ARM64_REG_X26, &regs->x26);
    uc_reg_read(uc, UC_ARM64_REG_X27, &regs->x27);
    uc_reg_read(uc, UC_ARM64_REG_X28, &regs->x28);
    uc_reg_read(uc, UC_ARM64_REG_FP, &regs->fp);
    uc_reg_read(uc, UC_ARM64_REG_LR, &regs->lr);
    uc_reg_read(uc, UC_ARM64_REG_SP, &regs->sp);
    uc_reg_read(uc, UC_ARM64_REG_PC, &regs->pc);
    
    uc_reg_read(uc, UC_ARM64_REG_S0, &regs->s0);
    uc_reg_read(uc, UC_ARM64_REG_S1, &regs->s1);
    uc_reg_read(uc, UC_ARM64_REG_S2, &regs->s2);
    uc_reg_read(uc, UC_ARM64_REG_S3, &regs->s3);
    uc_reg_read(uc, UC_ARM64_REG_S4, &regs->s4);
    uc_reg_read(uc, UC_ARM64_REG_S5, &regs->s5);
    uc_reg_read(uc, UC_ARM64_REG_S6, &regs->s6);
    uc_reg_read(uc, UC_ARM64_REG_S7, &regs->s7);
    uc_reg_read(uc, UC_ARM64_REG_S8, &regs->s8);
    uc_reg_read(uc, UC_ARM64_REG_S9, &regs->s9);
    uc_reg_read(uc, UC_ARM64_REG_S10, &regs->s10);
    uc_reg_read(uc, UC_ARM64_REG_S11, &regs->s11);
    uc_reg_read(uc, UC_ARM64_REG_S12, &regs->s12);
    uc_reg_read(uc, UC_ARM64_REG_S13, &regs->s13);
    uc_reg_read(uc, UC_ARM64_REG_S14, &regs->s14);
    uc_reg_read(uc, UC_ARM64_REG_S15, &regs->s15);
    uc_reg_read(uc, UC_ARM64_REG_S16, &regs->s16);
    uc_reg_read(uc, UC_ARM64_REG_S17, &regs->s17);
    uc_reg_read(uc, UC_ARM64_REG_S18, &regs->s18);
    uc_reg_read(uc, UC_ARM64_REG_S19, &regs->s19);
    uc_reg_read(uc, UC_ARM64_REG_S20, &regs->s20);
    uc_reg_read(uc, UC_ARM64_REG_S21, &regs->s21);
    uc_reg_read(uc, UC_ARM64_REG_S22, &regs->s22);
    uc_reg_read(uc, UC_ARM64_REG_S23, &regs->s23);
    uc_reg_read(uc, UC_ARM64_REG_S24, &regs->s24);
    uc_reg_read(uc, UC_ARM64_REG_S25, &regs->s25);
    uc_reg_read(uc, UC_ARM64_REG_S26, &regs->s26);
    uc_reg_read(uc, UC_ARM64_REG_S27, &regs->s27);
    uc_reg_read(uc, UC_ARM64_REG_S28, &regs->s28);
    uc_reg_read(uc, UC_ARM64_REG_S29, &regs->s29);
    uc_reg_read(uc, UC_ARM64_REG_S30, &regs->s30);
    uc_reg_read(uc, UC_ARM64_REG_S31, &regs->s31);
}

void uc_write_reg_state(uc_engine *uc, struct uc_reg_state *regs)
{
    uc_reg_write(uc, UC_ARM64_REG_X0, &regs->x0);
    uc_reg_write(uc, UC_ARM64_REG_X1, &regs->x1);
    uc_reg_write(uc, UC_ARM64_REG_X2, &regs->x2);
    uc_reg_write(uc, UC_ARM64_REG_X3, &regs->x3);
    uc_reg_write(uc, UC_ARM64_REG_X4, &regs->x4);
    uc_reg_write(uc, UC_ARM64_REG_X5, &regs->x5);
    uc_reg_write(uc, UC_ARM64_REG_X6, &regs->x6);
    uc_reg_write(uc, UC_ARM64_REG_X7, &regs->x7);
    uc_reg_write(uc, UC_ARM64_REG_X8, &regs->x8);
    uc_reg_write(uc, UC_ARM64_REG_X9, &regs->x9);
    uc_reg_write(uc, UC_ARM64_REG_X10, &regs->x10);
    uc_reg_write(uc, UC_ARM64_REG_X11, &regs->x11);
    uc_reg_write(uc, UC_ARM64_REG_X12, &regs->x12);
    uc_reg_write(uc, UC_ARM64_REG_X13, &regs->x13);
    uc_reg_write(uc, UC_ARM64_REG_X14, &regs->x14);
    uc_reg_write(uc, UC_ARM64_REG_X15, &regs->x15);
    uc_reg_write(uc, UC_ARM64_REG_X16, &regs->x16);
    uc_reg_write(uc, UC_ARM64_REG_X17, &regs->x17);
    uc_reg_write(uc, UC_ARM64_REG_X18, &regs->x18);
    uc_reg_write(uc, UC_ARM64_REG_X19, &regs->x19);
    uc_reg_write(uc, UC_ARM64_REG_X20, &regs->x20);
    uc_reg_write(uc, UC_ARM64_REG_X21, &regs->x21);
    uc_reg_write(uc, UC_ARM64_REG_X22, &regs->x22);
    uc_reg_write(uc, UC_ARM64_REG_X23, &regs->x23);
    uc_reg_write(uc, UC_ARM64_REG_X24, &regs->x24);
    uc_reg_write(uc, UC_ARM64_REG_X25, &regs->x25);
    uc_reg_write(uc, UC_ARM64_REG_X26, &regs->x26);
    uc_reg_write(uc, UC_ARM64_REG_X27, &regs->x27);
    uc_reg_write(uc, UC_ARM64_REG_X28, &regs->x28);
    uc_reg_write(uc, UC_ARM64_REG_FP, &regs->fp);
    uc_reg_write(uc, UC_ARM64_REG_LR, &regs->lr);
    uc_reg_write(uc, UC_ARM64_REG_SP, &regs->sp);
    uc_reg_write(uc, UC_ARM64_REG_PC, &regs->pc);
    
    uc_reg_write(uc, UC_ARM64_REG_S0, &regs->s0);
    uc_reg_write(uc, UC_ARM64_REG_S1, &regs->s1);
    uc_reg_write(uc, UC_ARM64_REG_S2, &regs->s2);
    uc_reg_write(uc, UC_ARM64_REG_S3, &regs->s3);
    uc_reg_write(uc, UC_ARM64_REG_S4, &regs->s4);
    uc_reg_write(uc, UC_ARM64_REG_S5, &regs->s5);
    uc_reg_write(uc, UC_ARM64_REG_S6, &regs->s6);
    uc_reg_write(uc, UC_ARM64_REG_S7, &regs->s7);
    uc_reg_write(uc, UC_ARM64_REG_S8, &regs->s8);
    uc_reg_write(uc, UC_ARM64_REG_S9, &regs->s9);
    uc_reg_write(uc, UC_ARM64_REG_S10, &regs->s10);
    uc_reg_write(uc, UC_ARM64_REG_S11, &regs->s11);
    uc_reg_write(uc, UC_ARM64_REG_S12, &regs->s12);
    uc_reg_write(uc, UC_ARM64_REG_S13, &regs->s13);
    uc_reg_write(uc, UC_ARM64_REG_S14, &regs->s14);
    uc_reg_write(uc, UC_ARM64_REG_S15, &regs->s15);
    uc_reg_write(uc, UC_ARM64_REG_S16, &regs->s16);
    uc_reg_write(uc, UC_ARM64_REG_S17, &regs->s17);
    uc_reg_write(uc, UC_ARM64_REG_S18, &regs->s18);
    uc_reg_write(uc, UC_ARM64_REG_S19, &regs->s19);
    uc_reg_write(uc, UC_ARM64_REG_S20, &regs->s20);
    uc_reg_write(uc, UC_ARM64_REG_S21, &regs->s21);
    uc_reg_write(uc, UC_ARM64_REG_S22, &regs->s22);
    uc_reg_write(uc, UC_ARM64_REG_S23, &regs->s23);
    uc_reg_write(uc, UC_ARM64_REG_S24, &regs->s24);
    uc_reg_write(uc, UC_ARM64_REG_S25, &regs->s25);
    uc_reg_write(uc, UC_ARM64_REG_S26, &regs->s26);
    uc_reg_write(uc, UC_ARM64_REG_S27, &regs->s27);
    uc_reg_write(uc, UC_ARM64_REG_S28, &regs->s28);
    uc_reg_write(uc, UC_ARM64_REG_S29, &regs->s29);
    uc_reg_write(uc, UC_ARM64_REG_S30, &regs->s30);
    uc_reg_write(uc, UC_ARM64_REG_S31, &regs->s31);
}

void uc_print_regs(uc_engine *uc)
{
    uint64_t x0, x1, x2, x3, x4, x5 ,x6 ,x7, x8;
    uint64_t x9, x10, x11, x12, x13, x14, x15, x16;
    uint64_t x17, x18, x19, x20, x21, x22, x23, x24;
    uint64_t x25, x26, x27, x28, fp, lr, sp, pc;
    
    if (!logmask_is_set(LOGMASK_DEBUG)) return;
    
    uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
    uc_reg_read(uc, UC_ARM64_REG_X1, &x1);
    uc_reg_read(uc, UC_ARM64_REG_X2, &x2);
    uc_reg_read(uc, UC_ARM64_REG_X3, &x3);
    uc_reg_read(uc, UC_ARM64_REG_X4, &x4);
    uc_reg_read(uc, UC_ARM64_REG_X5, &x5);
    uc_reg_read(uc, UC_ARM64_REG_X6, &x6);
    uc_reg_read(uc, UC_ARM64_REG_X7, &x7);
    uc_reg_read(uc, UC_ARM64_REG_X8, &x8);
    uc_reg_read(uc, UC_ARM64_REG_X9, &x9);
    uc_reg_read(uc, UC_ARM64_REG_X10, &x10);
    uc_reg_read(uc, UC_ARM64_REG_X11, &x11);
    uc_reg_read(uc, UC_ARM64_REG_X12, &x12);
    uc_reg_read(uc, UC_ARM64_REG_X13, &x13);
    uc_reg_read(uc, UC_ARM64_REG_X14, &x14);
    uc_reg_read(uc, UC_ARM64_REG_X15, &x15);
    uc_reg_read(uc, UC_ARM64_REG_X16, &x16);
    uc_reg_read(uc, UC_ARM64_REG_X17, &x17);
    uc_reg_read(uc, UC_ARM64_REG_X18, &x18);
    uc_reg_read(uc, UC_ARM64_REG_X19, &x19);
    uc_reg_read(uc, UC_ARM64_REG_X20, &x20);
    uc_reg_read(uc, UC_ARM64_REG_X21, &x21);
    uc_reg_read(uc, UC_ARM64_REG_X22, &x22);
    uc_reg_read(uc, UC_ARM64_REG_X23, &x23);
    uc_reg_read(uc, UC_ARM64_REG_X24, &x24);
    uc_reg_read(uc, UC_ARM64_REG_X25, &x25);
    uc_reg_read(uc, UC_ARM64_REG_X26, &x26);
    uc_reg_read(uc, UC_ARM64_REG_X27, &x27);
    uc_reg_read(uc, UC_ARM64_REG_X28, &x28);
    uc_reg_read(uc, UC_ARM64_REG_FP, &fp);
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
    uc_reg_read(uc, UC_ARM64_REG_SP, &sp);
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc);

    printf_debug("Register dump:\n");
    printf_debug("x0  %16.16" PRIx64 " ", x0);
    printf("x1  %16.16" PRIx64 " ", x1);
    printf("x2  %16.16" PRIx64 " ", x2);
    printf("x3  %16.16" PRIx64 " ", x3);
    printf("\n");
    printf_debug("x4  %16.16" PRIx64 " ", x4);
    printf("x5  %16.16" PRIx64 " ", x5);
    printf("x6  %16.16" PRIx64 " ", x6);
    printf("x7  %16.16" PRIx64 " ", x7);
    printf("\n");
    printf_debug("x8  %16.16" PRIx64 " ", x8);
    printf("x9  %16.16" PRIx64 " ", x9);
    printf("x10 %16.16" PRIx64 " ", x10);
    printf("x11 %16.16" PRIx64 " ", x11);
    printf("\n");
    printf_debug("x12 %16.16" PRIx64 " ", x12);
    printf("x13 %16.16" PRIx64 " ", x13);
    printf("x14 %16.16" PRIx64 " ", x14);
    printf("x15 %16.16" PRIx64 " ", x15);
    printf("\n");
    printf_debug("x16 %16.16" PRIx64 " ", x16);
    printf("x17 %16.16" PRIx64 " ", x17);
    printf("x18 %16.16" PRIx64 " ", x18);
    printf("x19 %16.16" PRIx64 " ", x19);
    printf("\n");
    printf_debug("x20 %16.16" PRIx64 " ", x20);
    printf("x21 %16.16" PRIx64 " ", x21);
    printf("x22 %16.16" PRIx64 " ", x22);
    printf("x23 %16.16" PRIx64 " ", x23);
    printf("\n");
    printf_debug("x24 %16.16" PRIx64 " ", x24);
    printf("x25 %16.16" PRIx64 " ", x25);
    printf("x26 %16.16" PRIx64 " ", x26);
    printf("x27 %16.16" PRIx64 " ", x27);
    printf("\n");
    printf_debug("x28 %16.16" PRIx64 " ", x28);
    printf("\n");
    printf_debug("fp  %16.16" PRIx64 " ", fp);
    printf("lr  %16.16" PRIx64 " ", lr);
    printf("sp  %16.16" PRIx64 " ", sp);
    printf("pc  %16.16" PRIx64 " ", pc);
    
    
    printf("\n");
}

void hook_code(uc_engine *uc, uint64_t address, uint32_t size, uc_inst* inst)
{
    static uint64_t last_pc[2];

    if (last_pc[0] == address && last_pc[0] == last_pc[1] && !inst->is_term())
    {
        printf_warn("Hang at 0x%" PRIx64 " ?\n", address);
        inst->terminate();
    }

    if (trace_code && !inst->is_term())
    {
        //printf(">>> Tracing instruction at 0x%" PRIx64 ", instruction size = 0x%x\n", address, size);
        //uc_print_regs(uc);
    }
    
    last_pc[1] = last_pc[0];
    last_pc[0] = address;
}

void remove_matching_tokens(uint64_t addr, std::string str)
{
    for (auto& pair : tokens)
    {
        std::vector<L2C_Token> to_erase;
        for (auto& t : pair.second)
        {
            if (t.pc == addr && t.str == str)
            {
                to_erase.push_back(t);
            }
        }

        for (auto& t : to_erase)
        {
            pair.second.erase(t);
        }
    }
}

void remove_block_matching_tokens(uint64_t block, uint64_t addr, std::string str)
{
    std::vector<L2C_Token> to_erase;
    for (auto& t : tokens[block])
    {
        if (t.pc == addr && t.str == str)
        {
            to_erase.push_back(t);
        }
    }

    for (auto& t : to_erase)
    {
        tokens[block].erase(t);
    }
}

bool token_by_addr_and_name_exists(uint64_t pc, std::string str)
{
    for (auto& pair : tokens)
    {
        for (auto& t : pair.second)
        {
            if (t.pc == pc && t.str == str)
            {
                return true;
            }
        }
    }
    
    return false;
}

void add_token_by_prio(uc_inst* inst, uint64_t block, L2C_Token token)
{
    for (auto& pair : tokens)
    {
        std::set<L2C_Token> to_erase;
        for (auto& t : pair.second)
        {
            if (t.pc == token.pc && t.str == token.str && token.fork_hierarchy.size() < t.fork_hierarchy.size())
            {
                to_erase.insert(t);
            }
            else if (t.pc == token.pc && t.str == token.str && token.fork_hierarchy.size() == t.fork_hierarchy.size() && t.fork_hierarchy[0] > token.fork_hierarchy[0])
            {
                to_erase.insert(t);
            }
            else if (t.pc == token.pc && t.str == token.str && token.fork_hierarchy.size() > t.fork_hierarchy.size())
            {
                return;
            }
        }

        for (auto& t : to_erase)
        {
            pair.second.erase(t);
        }
    }

    //printf("%llx\n", block);
    //token.print();

    tokens[block].insert(token);
    inst->inc_outputted_tokens();
}

void add_subreplace_token(uc_inst* inst, uint64_t block, L2C_Token token)
{
    std::set<L2C_Token> to_erase;
    for (auto& t : tokens[block])
    {
        if ((t.pc == token.pc && t.str == "SUB_BRANCH") 
            || (t.str == "SUB_GOTO" && t.args[0] == inst->get_current_block()))
        {
            to_erase.insert(t);
        }
    }

    bool function_tail = false;
    for (auto& t : to_erase)
    {
        tokens[block].erase(t);
        
        if (t.str == "SUB_GOTO")
            function_tail = true;
    }

    add_token_by_prio(inst, block, token);
    
    if (function_tail)
    {
        token.str = "SUB_RET";
        token.type = L2C_TokenType_Meta;
        token.args.clear();
        token.fargs.clear();
        add_token_by_prio(inst, block, token);
        
        inst->pop_block();
        
        if (token.pc+4 >= blocks[block].addr_end)
            blocks[block].addr_end = token.pc+4;
    }
}

uint64_t find_containing_block(uint64_t addr)
{
    for (auto& block_pair : blocks)
    {
        auto& block = block_pair.second;

        if (addr >= block.addr && addr < block.addr_end)
        {
            return block.addr;
        }
    }
    
    return 0;
}

void hook_import(uc_engine *uc, uint64_t address, uint32_t size, uc_inst* inst)
{
    uint64_t lr, origin;
    std::string name = unresolved_syms_rev[address];
    
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
    origin = inst->get_jump_history();
    printf_verbose("Instance Id %u: Import '%s' from %" PRIx64 ", size %x, block %" PRIx64 "\n", inst->get_id(), name.c_str(), origin, size, inst->get_last_block());
    invalidate_blocktree(inst, inst->get_current_block());
    
    // Add token
    L2C_Token token;
    token.pc = origin;
    token.fork_hierarchy = inst->get_fork_hierarchy();
    token.str = name;
    token.type = L2C_TokenType_Func;

    if (!inst->is_basic_emu() && converge_points[origin] && inst->has_parent() && inst->get_start_addr())
    {
        // Don't terminate if the token at the convergence point has a larger fork hierarchy
        // Too large a fork hierarchy just means one of the forks got ahead of the root
        // instance and the tokens will be replaced by correct values.
        bool should_term = false;
        uint64_t term_block = 0;
        for (auto& pair : tokens)
        {
            for (auto& t : pair.second)
            {
                //if (t.pc == origin)
                    //printf("conv %u: %llx %s %zx %zx\n", inst->get_id(), t.pc, t.str.c_str(), token.fork_hierarchy.size(), t.fork_hierarchy.size());
                if (t.pc == origin && (t.type == L2C_TokenType_Func || t.type == L2C_TokenType_Branch))
                {
                    if (token.fork_hierarchy.size() > t.fork_hierarchy.size())
                    {
                        //printf("doconv %u: %llx %s\n", inst->get_id(), t.pc, t.str.c_str());
                        should_term = true;
                        term_block = pair.first;
                    }
                    else if (token.fork_hierarchy.size() == t.fork_hierarchy.size())
                    {
                        should_term = token.fork_hierarchy[0] >= t.fork_hierarchy[0];
                        term_block = pair.first;
                    }
                }
                
                if (should_term) break;
            }
            if (should_term) break;
        }
        
        if (should_term)
        {
            printf_debug("Instance Id %u: Found convergence at %" PRIx64 ", outputted %u tokens\n", inst->get_id(), origin, inst->num_outputted_tokens());
            
            //TODO: split blocks
            if (inst->get_last_block() != term_block)
            {
                printf_warn("Instance Id %u: Convergence block is not the same as current block (%" PRIx64 ", %" PRIx64 ")...\n", inst->get_id(), inst->get_last_block(), term_block);
            }
            
            token.str = "CONV";
            token.type = L2C_TokenType_Meta;
            
            token.args.push_back(origin);
            token.args.push_back(term_block);
            //token.args.push_back(next_closest_block(inst->get_last_block(), origin));
            
            // Sometimes we get branches which just do nothing, pretend they don't exist
            if (inst->num_outputted_tokens())
                add_token_by_prio(inst, inst->get_last_block(), token);
            inst->terminate();
            return;
        }
    }

    bool add_token = false;
    if (!inst->is_basic_emu() && converge_points[origin])
    {
        for (auto& pair : tokens)
        {
            std::set<L2C_Token> to_erase;
            for (auto& t : pair.second)
            {
                if (t.pc == origin && t.type == L2C_TokenType_Func)
                {
                    if (token.fork_hierarchy.size() < t.fork_hierarchy.size())
                    {
                        to_erase.insert(t);
                        add_token = true;
                    }
                    else if (token.fork_hierarchy.size() == t.fork_hierarchy.size()
                             && token.fork_hierarchy[0] < t.fork_hierarchy[0])
                    {
                        to_erase.insert(t);
                        add_token = true;
                    }
                }
            }
            
            for (auto& t : to_erase)
            {
                pair.second.erase(t);
            }
        }
    }
    else if (!inst->is_basic_emu())
    {
        add_token = true;
    }

    // Write out a magic PC val which will cause Unicorn to fault.
    // This allows for faster run time while there isn't a fork,
    // since more instructions can be ran at once.
    // Also helps to synchronize fork+parent PC vals when a fork
    // does happen.
    uint64_t magic = MAGIC_IMPORT;
    uc_reg_write(uc, UC_ARM64_REG_PC, &magic);
    
    uint64_t args[9];
    float fargs[9];
    uc_reg_read(uc, UC_ARM64_REG_X0, &args[0]);
    uc_reg_read(uc, UC_ARM64_REG_X1, &args[1]);
    uc_reg_read(uc, UC_ARM64_REG_X2, &args[2]);
    uc_reg_read(uc, UC_ARM64_REG_X3, &args[3]);
    uc_reg_read(uc, UC_ARM64_REG_X4, &args[4]);
    uc_reg_read(uc, UC_ARM64_REG_X5, &args[5]);
    uc_reg_read(uc, UC_ARM64_REG_X6, &args[6]);
    uc_reg_read(uc, UC_ARM64_REG_X7, &args[7]);
    uc_reg_read(uc, UC_ARM64_REG_X8, &args[8]);
    
    uc_reg_read(uc, UC_ARM64_REG_S0, &fargs[0]);
    uc_reg_read(uc, UC_ARM64_REG_S1, &fargs[1]);
    uc_reg_read(uc, UC_ARM64_REG_S2, &fargs[2]);
    uc_reg_read(uc, UC_ARM64_REG_S3, &fargs[3]);
    uc_reg_read(uc, UC_ARM64_REG_S4, &fargs[4]);
    uc_reg_read(uc, UC_ARM64_REG_S5, &fargs[5]);
    uc_reg_read(uc, UC_ARM64_REG_S6, &fargs[6]);
    uc_reg_read(uc, UC_ARM64_REG_S7, &fargs[7]);
    uc_reg_read(uc, UC_ARM64_REG_S8, &fargs[8]);

    converge_points[origin] = true;
    
    if (name == "operator new(unsigned long)")
    {
        uint64_t alloc = inst->heap_alloc(args[0]);
        
        //TODO
        if (args[0] > 0x48)
            hash_cheat_ptr = alloc;
        
        args[0] = alloc;
    }
    else if (name == "lib::L2CAgent::sv_set_function_hash(void*, phx::Hash40)")
    {
        printf_info("Instance Id %u: lib::L2CAgent::sv_set_function_hash(0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64 ")\n", inst->get_id(), args[0], args[1], args[2]);
        
        function_hashes[std::pair<uint64_t, uint64_t>(args[0], args[2])] = args[1];
    }
    else if (name == "lua2cpp::L2CAgentBase::sv_set_status_func(lib::L2CValue const&, lib::L2CValue const&, void*)")
    {
        L2CValue* a = (L2CValue*)inst->uc_ptr_to_real_ptr(args[1]);
        L2CValue* b = (L2CValue*)inst->uc_ptr_to_real_ptr(args[2]);
        uint64_t funcptr = args[3];
        
        printf_info("Instance Id %u: lua2cpp::L2CAgentBase::sv_set_status_func(0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64 ")\n", inst->get_id(), args[0], a->raw, b->raw, funcptr);
        
        function_hashes[std::pair<uint64_t, uint64_t>(args[0], a->raw << 32 | b->raw)] = funcptr;
    }
    else if (name == "lib::utility::Variadic::get_format() const")
    {
        args[0] = 0;
    }
    else if (name == "lib::L2CAgent::clear_lua_stack()")
    {
        inst->lua_stack = std::vector<L2CValue>();
    }
    else if (name == "app::sv_animcmd::is_excute(lua_State*)")
    {
        inst->lua_stack.push_back(L2CValue(true));
    }
    else if (name == "app::sv_animcmd::frame(lua_State*, float)")
    {
        token.args.push_back(args[0]);
        token.fargs.push_back(fargs[0]);

        inst->lua_stack.push_back(L2CValue(true));
    }
    else if (name == "lib::L2CAgent::pop_lua_stack(int)")
    {
        token.args.push_back(args[1]);
    
        L2CValue* out = (L2CValue*)inst->uc_ptr_to_real_ptr(args[8]);
        L2CValue* iter = out;

        for (int i = 0; i < args[1]; i++)
        {
            if (!out) break;

            if (inst->lua_stack.size())
            {
                *iter = *(inst->lua_stack.end() - 1);
                inst->lua_stack.pop_back();
            }
            else
            {
                //printf_warn("Instance Id %u: Bad stack pop...\n", inst->get_id());
                
                L2CValue empty();
                *iter = empty;
            }

            iter++;
        }
        
        //inst->lua_active_vars[args[8]] = out;
    }
    else if (name == "lib::L2CAgent::push_lua_stack(lib::L2CValue const&)")
    {
        L2CValue* val = (L2CValue*)inst->uc_ptr_to_real_ptr(args[1]);
        
        if (val)
        {
            token.args.push_back(val->type);
            if (val->type != L2C_number)
            {
                token.args.push_back(val->raw);
            }
            else
            {
                token.fargs.push_back(val->as_number());
            }
            
        }
    }
    else if (name == "lib::L2CValue::L2CValue(int)")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);
        if (var)
            *var = L2CValue((int)args[1]);
        else
            printf_error("Instance Id %u: Bad L2CValue init, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    
        token.args.push_back((int)args[1]);
        //add_token = false;
        //purge_markers(token.pc);
    }
    else if (name == "lib::L2CValue::L2CValue(long)")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);
        if (var)
            *var = L2CValue((long)args[1]);
        else
            printf_error("Instance Id %u: Bad L2CValue init, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    
        token.args.push_back((long)args[1]);
        //add_token = false;
        //purge_markers(token.pc);
    }
    else if (name == "lib::L2CValue::L2CValue(unsigned int)"
             || name == "lib::L2CValue::L2CValue(unsigned long)")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);
        if (var)
            *var = L2CValue(args[1]);
        else
            printf_error("Instance Id %u: Bad L2CValue init, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    
        token.args.push_back(args[1]);
        //add_token = false;
        //purge_markers(token.pc);
    }
    else if (name == "lib::L2CValue::L2CValue(bool)")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);
        if (var)
            *var = L2CValue((bool)args[1]);
        else
            printf_error("Instance Id %u: Bad L2CValue init, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    
        token.args.push_back((int)args[1]);
        //add_token = false;
        //purge_markers(token.pc);
    }
    else if (name == "lib::L2CValue::L2CValue(phx::Hash40)")
    {
        Hash40 hash = {args[1] & 0xFFFFFFFFFF};
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);
        if (var)
            *var = L2CValue(hash);
        else
            printf_error("Instance Id %u: Bad L2CValue init, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
        
        token.args.push_back(hash.hash);
        //add_token = false;
        //purge_markers(token.pc);
    }
    else if (name == "lib::L2CValue::L2CValue(void*)")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);
        if (var)
            *var = L2CValue((void*)args[1]);
        else
            printf_error("Instance Id %u: Bad L2CValue init, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
        
        token.args.push_back(args[1]);
        //add_token = false;
        //purge_markers(token.pc);
    }
    else if (name == "lib::L2CValue::L2CValue(float)")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);
        if (var)
            *var = L2CValue((float)fargs[0]);
        else
            printf_error("Instance Id %u: Bad L2CValue init, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
        
        token.fargs.push_back(fargs[0]);
        //add_token = false;
        //purge_markers(token.pc);
    }
    else if (name == "lib::L2CValue::as_number() const")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);

        if (var)
        {
            fargs[0] = var->as_number();
            token.fargs.push_back(var->as_number());
        }
        else
            printf_error("Instance Id %u: Bad L2CValue access, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    }
    else if (name == "lib::L2CValue::as_bool() const")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);

        if (var)
        {
            args[0] = var->as_bool();
            token.args.push_back(var->as_bool());
        }
        else
            printf_error("Instance Id %u: Bad L2CValue access, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    }
    else if (name == "lib::L2CValue::as_integer() const")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);

        if (var)
        {
            args[0] = var->as_integer();
            token.args.push_back(var->as_integer());
        }
        else
            printf_error("Instance Id %u: Bad L2CValue access, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    }
    else if (name == "lib::L2CValue::as_pointer() const")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);

        if (var)
        {
            args[0] = var->raw;
            token.args.push_back(var->raw);
        }
        else
            printf_error("Instance Id %u: Bad L2CValue access, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    }
    else if (name == "lib::L2CValue::as_table() const")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);

        if (var)
        {
            args[0] = var->raw;
            token.args.push_back(var->raw);
        }
        else
            printf_error("Instance Id %u: Bad L2CValue access, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    }
    else if (name == "lib::L2CValue::as_inner_function() const")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);

        if (var)
        {
            args[0] = var->raw;
            token.args.push_back(var->raw);
        }
        else
            printf_error("Instance Id %u: Bad L2CValue access, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    }
    else if (name == "lib::L2CValue::as_hash() const")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);

        if (var)
        {
            args[0] = var->as_hash();
            token.args.push_back(var->as_hash());
        }
        else
            printf_error("Instance Id %u: Bad L2CValue access, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    }
    else if (name == "lib::L2CValue::as_string() const")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);

        if (var)
        {
            args[0] = var->raw;
            token.args.push_back(var->raw);
        }
        else
            printf_error("Instance Id %u: Bad L2CValue access, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    }
    else if (name == "lib::L2CValue::~L2CValue()")
    {
        //inst->lua_active_vars[args[0]] = nullptr;
        //add_token = false;
        //purge_markers(token.pc);
    }
    else if (name == "lib::L2CValue::operator[](phx::Hash40) const")
    {
        if (!hash_cheat[args[1]])
        {
            hash_cheat[args[1]] = inst->heap_alloc(0x10);
        }

        uint64_t l2cval = hash_cheat[args[1]];
        hash_cheat_rev[l2cval] = args[1];

        printf_verbose("Hash cheating!! %llx\n", l2cval);
        
        args[0] = l2cval;
    }
    else if (name == "lib::L2CValue::operator=(lib::L2CValue const&)")
    {
        L2CValue* out = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);
        L2CValue* in = (L2CValue*)inst->uc_ptr_to_real_ptr(args[1]);
        
        if (in && out)
        {
            //TODO operator= destruction
            *out = *in;
            
            if (hash_cheat_rev[args[0]])
            {
                printf_verbose("Hash cheating! %llx => %llx\n", hash_cheat_rev[args[0]], in->raw);
                function_hashes[std::pair<uint64_t, uint64_t>(hash_cheat_ptr, hash_cheat_rev[args[0]])] = in->raw;
            }
        }
        else
        {
            printf_error("Instance Id %u: Bad L2CValue assignment @ " PRIx64 "!\n", inst->get_id(), origin);
        }
    }
    else if (name == "lib::L2CValue::operator bool() const"
             || name == "lib::L2CValue::operator==(lib::L2CValue const&) const"
             || name == "lib::L2CValue::operator<=(lib::L2CValue const&) const"
             || name == "lib::L2CValue::operator<(lib::L2CValue const&) const")
    {
        //TODO basic emu comparisons
        if (inst->is_basic_emu())
        {
            L2CValue* in = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);
            if (in)
                args[0] = in->as_bool();
            else
                args[0] = 0;
        }
        else
        {
            if (add_token)
                add_subreplace_token(inst, inst->get_last_block(), token);
            add_token = false;

            args[0] = 1;
            uc_reg_write(uc, UC_ARM64_REG_X0, &args[0]);    
            inst->fork_inst();

            args[0] = 0;
        }
    }

    uc_reg_write(uc, UC_ARM64_REG_X0, &args[0]);
    uc_reg_write(uc, UC_ARM64_REG_X1, &args[1]);
    uc_reg_write(uc, UC_ARM64_REG_X2, &args[2]);
    uc_reg_write(uc, UC_ARM64_REG_X3, &args[3]);
    uc_reg_write(uc, UC_ARM64_REG_X4, &args[4]);
    uc_reg_write(uc, UC_ARM64_REG_X5, &args[5]);
    uc_reg_write(uc, UC_ARM64_REG_X6, &args[6]);
    uc_reg_write(uc, UC_ARM64_REG_X7, &args[7]);
    uc_reg_write(uc, UC_ARM64_REG_X8, &args[8]);
    
    uc_reg_write(uc, UC_ARM64_REG_S0, &fargs[0]);
    uc_reg_write(uc, UC_ARM64_REG_S1, &fargs[1]);
    uc_reg_write(uc, UC_ARM64_REG_S2, &fargs[2]);
    uc_reg_write(uc, UC_ARM64_REG_S3, &fargs[3]);
    uc_reg_write(uc, UC_ARM64_REG_S4, &fargs[4]);
    uc_reg_write(uc, UC_ARM64_REG_S5, &fargs[5]);
    uc_reg_write(uc, UC_ARM64_REG_S6, &fargs[6]);
    uc_reg_write(uc, UC_ARM64_REG_S7, &fargs[7]);
    uc_reg_write(uc, UC_ARM64_REG_S8, &fargs[8]);
    
    if (add_token)
        add_subreplace_token(inst, inst->get_last_block(), token);
}

void hook_memrw(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, uc_inst* inst)
{
    switch(type) 
    {
        default: break;
        case UC_MEM_READ:
                 value = *(uint64_t*)(inst->uc_ptr_to_real_ptr(addr));
                 printf_verbose("Instance Id %u: Memory is being READ at 0x%" PRIx64 ", data size = %u, data value = 0x%" PRIx64 "\n", inst->get_id(), addr, size, value);
                 break;
        case UC_MEM_WRITE:
                 printf_verbose("Instance Id %u: Memory is being WRITE at 0x%" PRIx64 ", data size = %u, data value = 0x%" PRIx64 "\n", inst->get_id(), addr, size, value);
                 break;
    }
    return;
}

// callback for tracing memory access (READ or WRITE)
bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, uc_inst* inst)
{
    switch(type) {
        default:
            // return false to indicate we want to stop emulation
            return false;
        case UC_MEM_READ_UNMAPPED:
            printf_error("Instance Id %u: Missing memory is being READ at 0x%" PRIx64 ", data size = %u, data value = 0x%" PRIx64 " PC @ %" PRIx64 "\n", inst->get_id(), address, size, value, inst->get_pc());
            //uc_print_regs(uc);
            
            return false;
        case UC_MEM_WRITE_UNMAPPED:        
            printf_error("Instance Id %u: Missing memory is being WRITE at 0x%" PRIx64 ", data size = %u, data value = 0x%" PRIx64 " PC @ %" PRIx64 "\n", inst->get_id(), address, size, value, inst->get_pc());
            //uc_print_regs(uc);
            
            return true;
        case UC_ERR_EXCEPTION:
            if (address != MAGIC_IMPORT && inst->get_sp() != STACK_END)
                printf_error("Instance Id %u: Exception PC @ %" PRIx64 "\n", inst->get_id(), inst->get_pc());
            return false;
    }
}

void clean_and_verify_blocks(uint64_t func)
{
    std::map<uint64_t, bool> block_visited;
    std::vector<uint64_t> block_list;
    block_list.push_back(func);
    block_visited[func] = true;
    
    std::map<std::string, int> fork_token_instances;
    std::set<uint64_t> split_positions;
    std::map<uint64_t, bool> addr_in_block;
    std::map<uint64_t, bool> addr_in_token;
    
    while(block_list.size())
    {
        uint64_t b = *(block_list.end() - 1);
        block_list.pop_back();

        if (!tokens[b].size()) continue;

        L2C_Token last_token = L2C_Token();
        last_token.str = "";

        int num_jumps = 0;
        for (auto t : tokens[b])
        {
            if (t.str != "BLOCK_MERGE" && t.str != "SPLIT_BLOCK_MERGE" && t.str != "DIV_TRUE" && t.str != "SUB_RET")
            {
                if (addr_in_token[t.pc])
                    printf_warn("Token address overlap at %" PRIx64 " in block %" PRIx64 "\n", t.pc, b);

                addr_in_token[t.pc] = true;
            }
        
            if (t.str == "SUB_BRANCH" || t.str == "SUB_GOTO" || t.str == "DIV_FALSE" || t.str == "DIV_TRUE" || t.str == "CONV" || t.str == "BLOCK_MERGE" || t.str == "SPLIT_BLOCK_MERGE")
            {
                if (!block_visited[t.args[0]])
                {
                    block_list.push_back(t.args[0]);
                    block_visited[t.args[0]] = true;
                }
                
                if (!blocks[t.args[0]].num_tokens())
                {
                    printf_warn("Destination %" PRIx64 " from %s at %" PRIx64 " is empty!\n", t.args[0], t.str.c_str(), t.pc);
                }
            }
            
            if (t.str == "SUB_GOTO" || t.str == "DIV_FALSE" || t.str == "CONV" || t.str == "BLOCK_MERGE" || t.str == "SPLIT_BLOCK_MERGE" || t.str == "NORETURN" || t.str == "SUB_RET")
                num_jumps++;

            if (t.str == "DIV_TRUE" && last_token.str != "DIV_FALSE")
                printf_warn("Dangling DIV_TRUE at %" PRIx64 "\n", t.pc);

            if (last_token.str == "BLOCK_MERGE" || last_token.str == "SPLIT_BLOCK_MERGE" || last_token.str == "SUB_GOTO" || last_token.str == "CONV" || last_token.str == "DIV_TRUE")
            {
                printf_warn("%s found mid-block at %" PRIx64 " and not at end as expected!\n", last_token.str.c_str(), last_token.pc);
            }

            fork_token_instances[t.fork_hierarchy_str()]++;
            last_token = t;
        }
        
        if (last_token.str == "DIV_FALSE")
            printf_warn("Dangling DIV_FALSE at %" PRIx64 "\n", last_token.pc);
        
        for (uint64_t i = blocks[b].addr; i < blocks[b].addr_end; i += 4)
        {
            if (addr_in_block[i])
                printf_warn("Address range overlap at %" PRIx64 " in block %" PRIx64 "\n", i, b);
            addr_in_block[i] = true;
        }
        
        if (!num_jumps)
            printf_warn("Block %" PRIx64 " is missing an exit token!\n", b);
        else if (num_jumps > 1)
            printf_warn("Block %" PRIx64 " has too many exit tokens!\n", b);
        
        std::sort(block_list.begin(), block_list.end(), std::greater<int>()); 
    }
    
    for (auto& map_pair : fork_token_instances)
    {
        if (map_pair.second > 1) continue;

        for (auto& block_pair : tokens)
        {
            auto& block = block_pair.first;
            auto& block_tokens = block_pair.second;

            std::vector<L2C_Token> to_remove;
            for (auto& token : block_tokens)
            {
                std::string forkstr = token.fork_hierarchy_str();
                if (forkstr == map_pair.first && token.str == "CONV")
                {
                    to_remove.push_back(token);
                }
            }

            for (auto& token : to_remove)
            {
                if (logmask_is_set(LOGMASK_DEBUG))
                {
                    printf_debug("Pruning ");
                    token.print();
                }
                block_tokens.erase(token);
            }
        }
    }
}

std::map<uint64_t, bool> block_printed;

void print_block(uint64_t b)
{
    if (block_printed[b])
    {
        printf("\nBlock %" PRIx64 " type %u, size %x, %u tokens, creation %s: See earlier definition\n", blocks[b].hash(), blocks[b].type, blocks[b].size(), blocks[b].num_tokens(), blocks[b].fork_hierarchy_str().c_str());
        return;
    }

    //printf("\nBlock %" PRIx64 " (end %" PRIx64 ") type %u, size %x, %u tokens, creation %s:\n", b, blocks[b].addr_end, blocks[b].type, blocks[b].size(), blocks[b].num_tokens(), blocks[b].fork_hierarchy_str().c_str());
    printf("\nBlock %" PRIx64 " type %u, size %x, %u tokens, creation %s:\n", blocks[b].hash(), blocks[b].type, blocks[b].size(), blocks[b].num_tokens(), blocks[b].fork_hierarchy_str().c_str());
    for (auto t : tokens[b])
    {
        t.print(b);
    }
    
    block_printed[b] = true;
}

void print_blocks(uint64_t func, std::unordered_map<uint64_t, bool>* block_visited = nullptr)
{
    std::map<uint64_t, bool> block_skipped;
    std::set<uint64_t> block_visited_here;
    std::vector<uint64_t> block_list;
    block_list.push_back(func);

    bool needs_free = false;
    if (!block_visited)
    {
        block_visited = new std::unordered_map<uint64_t, bool>();
        needs_free = true;
    }
    
    if ((*block_visited)[func]) return;
    
    (*block_visited)[func] = true;
    block_visited_here.insert(func);
    
    //print_blocks(func);

    while(block_list.size())
    {
        uint64_t b = *(block_list.end() - 1);
        block_list.pop_back();

        if (!tokens[b].size()) continue;

        //print_block(b);
        for (auto t : tokens[b])
        {
            if (t.str == "SUB_BRANCH" || t.str == "SUB_GOTO" || t.str == "DIV_FALSE" || t.str == "DIV_TRUE" || t.str == "CONV" || t.str == "BLOCK_MERGE" || t.str == "SPLIT_BLOCK_MERGE")
            {
                if (!(*block_visited)[t.args[0]] && !block_skipped[t.args[0]] && t.str != "SUB_BRANCH")
                {
                    block_list.push_back(t.args[0]);
                    (*block_visited)[t.args[0]] = true;
                    block_visited_here.insert(t.args[0]);
                }
                else if (!(*block_visited)[t.args[0]])
                {
                    block_skipped[t.args[0]] = true;
                }
            }
        }
        
        //std::sort(block_list.begin(), block_list.end(), std::greater<int>());
    }
    
    for (auto b : block_visited_here)
    {
        print_block(b);
    }
    
    for (auto& pair : block_skipped)
    {
        uint64_t b = pair.first;
        
        print_blocks(b, block_visited);
    }
    
    if (needs_free) delete block_visited;
}

void invalidate_blocktree(uc_inst* inst, uint64_t func)
{
    std::map<uint64_t, bool> block_visited;
    std::vector<uint64_t> block_list;
    block_list.push_back(func);
    block_visited[func] = true;
    
    //print_blocks(func);

    while(block_list.size())
    {
        uint64_t b = *(block_list.end() - 1);
        block_list.pop_back();

        if (!tokens[b].size()) continue;

        for (auto t : tokens[b])
        {
            if (t.str == "SUB_BRANCH" || t.str == "SUB_GOTO" || t.str == "DIV_FALSE" || t.str == "DIV_TRUE" || t.str == "CONV" || t.str == "BLOCK_MERGE" || t.str == "SPLIT_BLOCK_MERGE")
            {
                if (!block_visited[t.args[0]])
                {
                    block_list.push_back(t.args[0]);
                    block_visited[t.args[0]] = true;
                }
            }
        }
        
        std::sort(block_list.begin(), block_list.end(), std::greater<int>());
    }
    
    for (auto& pair : block_visited)
    {
        printf_verbose("Instance Id %u: Invalidated block %" PRIx64 " (type %u) from chain %" PRIx64 "\n", inst->get_id(), pair.first, blocks[pair.first].type, func);
    
        for (uint64_t i = blocks[pair.first].addr; i < blocks[pair.first].addr_end; i++)
        {
            converge_points[i] = false;
            is_goto_dst[i] = false;
            is_fork_origin[i] = false;
        }
    
        // In case there's anything weird going on...
        for (auto& t : tokens[pair.first])
        {
            converge_points[t.pc] = false;
            is_goto_dst[t.pc] = false;
            is_fork_origin[t.pc] = false;
        }
    
        tokens[pair.first].clear();
        blocks[pair.first] = L2C_CodeBlock();
    }
    printf_verbose("Instance Id %u: Invalidated %u block(s)\n", inst->get_id(), block_visited.size());
}

int main(int argc, char **argv, char **envp)
{
    // lua2cpp::L2CFighterAnimcmdBase
    uint64_t animcmd_effect, animcmd_effect_share, animcmd_expression, animcmd_game, animcmd_sound;
    
    uint64_t x0, x1, x2, x3;
    x0 = hash40("wolf", 4); // Hash40
    x1 = 0xFFFE000000000000; // BattleObject
    x2 = 0xFFFD000000000000; // BattleObjectModuleAccessor
    x3 = 0xFFFC000000000000; // lua_state
    
    uc_inst inst = uc_inst();
    
    std::string agents[] = { "status_script", "animcmd_effect", "animcmd_effect_share", "animcmd_expression", "animcmd_expression_share", "animcmd_game", "animcmd_game_share", "animcmd_sound", "animcmd_sound_share", "ai_action", "ai_mode" };
    std::string objects[] { "", "_illusion", "_blaster_bullet" };
    std::string character = "wolf";
    std::map<std::string, uint64_t> l2cagents;
    std::map<uint64_t, std::string> l2cagents_rev;
    
    logmask_unset(LOGMASK_DEBUG | LOGMASK_INFO);
    //logmask_set(LOGMASK_VERBOSE);
    for (auto& agent : agents)
    {
        for (auto& object : objects)
        {
            std::string hashstr = character + object;
            std::string key = hashstr + "_" + agent;
            std::string func = "lua2cpp::create_agent_fighter_" + agent + "_" + character;
            std::string args = "(phx::Hash40, app::BattleObject*, app::BattleObjectModuleAccessor*, lua_State*)";
            
            x0 = hash40(hashstr.c_str(), hashstr.length()); // Hash40
            uint64_t funcptr = resolved_syms[func + args];
            
            printf_debug("Running %s(hash40(%s) => 0x%08x, ...)...\n", func.c_str(), hashstr.c_str(), x0);
            uint64_t output = inst.uc_run_stuff(funcptr, false, false, x0, x1, x2, x3);
            
            if (output)
            {
                printf("Got output %" PRIx64 " for %s(hash40(%s) => 0x%08x, ...), mapping to %s\n", output, func.c_str(), hashstr.c_str(), x0, key.c_str());
                l2cagents[key] = output;
                l2cagents_rev[output] = key;
                
                // Special MSC stuff, they store funcs in a vtable
                // so we run function 9 to actually set everything
                if (agent == "status_script")
                {
                    uint64_t vtable_ptr = *(uint64_t*)(inst.uc_ptr_to_real_ptr(output));
                    uint64_t* vtable = ((uint64_t*)(inst.uc_ptr_to_real_ptr(vtable_ptr)));
                    uint64_t func = vtable[9];

                    tokens.clear();
                    blocks.clear();
                    is_goto_dst.clear();
                    is_fork_origin.clear();
                    converge_points = std::map<uint64_t, bool>();
                    
                    inst.uc_run_stuff(func, true, true, output);
                    print_blocks(funcptr);
                }
            }
        }
    }
    //logmask_set(LOGMASK_DEBUG | LOGMASK_INFO);
    //logmask_set(LOGMASK_VERBOSE);

    // Set up L2CAgent
    //uint64_t l2cagent = inst.heap_alloc(0x1000);
    //L2CAgent* agent = (L2CAgent*)inst.uc_ptr_to_real_ptr(l2cagent);
    uint64_t luastate = inst.heap_alloc(0x1000);
    //agent->luastate = luastate;
    //lua_State* unk40 = (lua_State*)inst.uc_ptr_to_real_ptr(agent->luastate);
    
    for (int i = 0; i < 0x200; i += 8)
    {
        uint64_t class_alloc = inst.heap_alloc(0x100);
        uint64_t vtable_alloc = inst.heap_alloc(512 * sizeof(uint64_t));

        *(uint64_t*)(inst.uc_ptr_to_real_ptr(luastate + i)) = class_alloc;
        *(uint64_t*)(inst.uc_ptr_to_real_ptr(class_alloc)) = vtable_alloc;
        
        //printf("%llx %llx %llx\n", l2cagent, class_alloc, vtable_alloc);

        for (int j = 0; j < 512; j++)
        {
            uint64_t* out = (uint64_t*)inst.uc_ptr_to_real_ptr(vtable_alloc + j * sizeof(uint64_t));
            uint64_t addr = IMPORTS + (imports_size + 0x8);
            imports_size += 0x8;

            char tmp[256];
            snprintf(tmp, 256, "lua_State::off%XVtableFunc%u", i, j);
            
            /*if (i == 0x40 && j == 0x39)
            {
                printf("%s %llx\n", tmp, addr);
            }*/
            
            std::string name(tmp);
            
            unresolved_syms[name] = addr;
            unresolved_syms_rev[addr] = name;
            *out = addr;
            
            inst.add_import_hook(addr);
        }
    }
    
    for (auto& pair : l2cagents)
    {
        uint64_t l2cagent = pair.second;
        L2CAgent* agent = (L2CAgent*)inst.uc_ptr_to_real_ptr(l2cagent);
        agent->lua_state_agent = luastate;
        agent->lua_state_agentbase = luastate;
    }
    
    for (auto& pair : function_hashes)
    {
        auto regpair = pair.first;
        auto funcptr = pair.second;
  
        //if (regpair.first == l2cagents[character + "_status_script"])
        //if (regpair.first == l2cagents[character + "_animcmd_sound"])
        //if (funcptr == 0x1000ffe20)
        //if (funcptr == 0x1000eb140)
        //if (funcptr == 0x100101a20)
        {
            // String centering stuff

//#if 0
            printf(">--------------------------------------<\n");
            
            std::string agent_name = l2cagents_rev[regpair.first];
            for (int i = 0; i < 20 - (agent_name.length() / 2); i++)
            {
                printf(" ");
            }
            printf("%s\n", agent_name.c_str());
            
            
            printf("               %10" PRIx64 "\n", regpair.second);
//#endif
            //tokens.clear();
            //blocks.clear();
            is_goto_dst.clear();
            is_fork_origin.clear();
            converge_points = std::map<uint64_t, bool>();
            
            //printf("%s %10" PRIx64 " %8" PRIx64 "\n", l2cagents_rev[regpair.first].c_str(), regpair.second, funcptr);
            inst.uc_run_stuff(funcptr, true, true, regpair.first, 0xFFFA000000000000);

//#if 0
            printf("                %8" PRIx64 "\n", blocks[funcptr].hash());
            printf(">--------------------------------------<\n");
//#endif

            print_blocks(funcptr);
            //print_block(funcptr);

//#if 0
            printf("<-------------------------------------->\n");
//#endif
        }
    }
    
    // Print all blocks
    /*for (auto& pair : tokens)
    {
        uint64_t block = pair.first;
        if (pair.second.size())
            print_block(block);
    }*/
    
        
    tokens.clear();
    blocks.clear();
    is_goto_dst.clear();
    is_fork_origin.clear();
    converge_points = std::map<uint64_t, bool>();
    
    // return function as branch
    uint64_t some_func = function_hashes[std::pair<uint64_t, uint64_t>(l2cagents[character + "_animcmd_effect"], hash40("effect_landinglight", 19))];
    //inst.uc_run_stuff(some_func, true, true, l2cagents[character + "_animcmd_effect"], 0xFFFA000000000000);
    //print_blocks(some_func);
    
    // while loop
    uint64_t while_func = function_hashes[std::pair<uint64_t, uint64_t>(l2cagents[character + "_animcmd_effect"], 0x15a34492fd)];
    //inst.uc_run_stuff(while_func, true, true, l2cagents[character + "_animcmd_effect"], 0xFFFA000000000000);
    //print_blocks(while_func);
    
    // while loop 2
    uint64_t while_func_2 = function_hashes[std::pair<uint64_t, uint64_t>(l2cagents[character + "_animcmd_effect"], 0xa8a5ccccf)];
    //inst.uc_run_stuff(while_func_2, true, true, l2cagents[character + "_animcmd_effect"], 0xFFFA000000000000);
    //print_blocks(while_func_2);
    
    // complicated ifs
    uint64_t some_func2 = function_hashes[std::pair<uint64_t, uint64_t>(l2cagents[character + "_animcmd_sound"], 0x1692b4de28)];
    //inst.uc_run_stuff(some_func2, true, true, l2cagents[character + "_animcmd_sound"], 0xFFFA000000000000);
    //print_blocks(some_func2);
    
    // subroutines w/ ifs
    //inst.uc_run_stuff(0x10011a470, true, true, l2cagent, 0xFFFA000000000000);
    //print_blocks(0x10011a470);
    
    // subroutine immediately following if
    //inst.uc_run_stuff(0x1000f08d0, true, true, l2cagent, 0xFFFA000000000000);
    //print_blocks(0x1000f08d0);
    
    // super stress test; subroutines, splitting
    //inst.uc_run_stuff(0x1000ec3a0, true, true, l2cagent, 0xFFFA000000000000);
    //print_blocks(0x1000ec3a0);
    
    // weird splitting
    //inst.uc_run_stuff(0x1000ece90, true, true, l2cagent, 0xFFFA000000000000);
    //print_blocks(0x1000ece90);
    
    /*
    >--------------------------------------<
         wolf_animcmd_expression
                e9adee448
                100102af0
>--------------------------------------<
[ERROR] Instance Id 2: Missing memory is being READ at 0x48, data size = 8, data value = 0x0 PC @ 10004a2f8
[ERROR] Instance Id 2: Failed on uc_emu_start() with error returned: 6
[ERROR] Instance Id 3: Missing memory is being READ at 0x48, data size = 8, data value = 0x0 PC @ 10004a408
[ERROR] Instance Id 3: Failed on uc_emu_start() with error returned: 6
[ERROR] Instance Id 4: Missing memory is being READ at 0x48, data size = 8, data value = 0x0 PC @ 10004a518
[ERROR] Instance Id 4: Failed on uc_emu_start() with error returned: 6
[ERROR] Instance Id 5: Missing memory is being READ at 0x48, data size = 8, data value = 0x0 PC @ 10004a628
[ERROR] Instance Id 5: Failed on uc_emu_start() with error returned: 6
[WARN] Block 10004a2b0 is missing an exit token!
[WARN] Block 10004a3c0 is missing an exit token!
[WARN] Block 10004a4d0 is missing an exit token!
[WARN] Block 10004a5e0 is missing an exit token!
    */

    return 0;
}
