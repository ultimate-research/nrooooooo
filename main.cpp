#include "main.h"

#include <string.h>
#include <time.h>
#include <iostream>
#include <filesystem>
#include <list>
#include <elf.h>
#include <vector>
#include <map>
#include "crc32.h"

extern "C"
{
extern char *
cplus_demangle (const char *mangled, int options);
}

std::map<std::string, uint64_t> unresolved_syms;
std::map<uint64_t, std::string> unresolved_syms_rev;
std::map<std::string, uint64_t> resolved_syms;

// memory addresses for different segments
#define NRO 0x100000000
#define NRO_SIZE (0x2000000)
void* nro;

#define IMPORTS 0xEEEE000000000000
#define IMPORTS_SIZE (0x800000)
void* imports;

#define HEAP 0xBBBB000000000000
#define HEAP_SIZE (0x800000)
void* heap;
uint64_t heap_size = 0;

#define STACK 0xFFFF000000000000
#define STACK_SIZE (0x100000)
void* stack;

bool uc_quit = false;
bool trace_code = true;

uc_engine *cores[4];
uc_context *core_contexts[4];
bool cores_online[4] = {false, false, false, false};    


void** elfs = NULL;
uint32_t num_elfs = 0;

void** builtin_elfs = NULL;
uint32_t num_builtin_elfs = 0;

struct nso_header
{
    uint32_t start;
    uint32_t mod;
};

struct mod0_header
{
    uint32_t magic;
    uint32_t dynamic;
};

uint64_t nro_assignsyms(void* base)
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
        }
    }
    
    numsyms = ((uintptr_t)strtab - (uintptr_t)symtab) / sizeof(Elf64_Sym);
    
    for (int i = 0; i < numsyms; i++)
    {
        char* demangled = cplus_demangle(strtab + symtab[i].st_name, 0);
        printf("%s %llx %x\n", demangled, symtab[i].st_value, symtab[i].st_shndx);
        
        if (symtab[i].st_shndx == 0 && demangled)
        {
            uint64_t addr = IMPORTS + (i * 0x1000);
            unresolved_syms[std::string(demangled)] = addr;
            unresolved_syms_rev[addr] = std::string(demangled);
        }
        else if (symtab[i].st_shndx && demangled)
        {
            resolved_syms[std::string(demangled)] = NRO + symtab[i].st_value;
        }
        free(demangled);
    }

    return 0;
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

        //if (!symtab[sym_idx].st_shndx && sym_idx)
            //sym_val = SaltySDCore_FindSymbol(name);

        uint64_t sym_val_and_addend = sym_val + rela->r_addend;

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
                char* demangled = cplus_demangle(name, 0);
                
                if (demangled)
                {
                    printf("@ %llx, %s -> %llx, %llx\n", NRO + rela->r_offset, demangled, unresolved_syms[std::string(demangled)], *ptr);
                    *ptr = unresolved_syms[std::string(demangled)];
                    free(demangled);
                }
                break;
            }
            default:
            {
                printf("Unknown relocation type %u\n", ELF64_R_TYPE(rela->r_info));
                break;
            }
        }
    }
    
    /*numsyms = ((uintptr_t)strtab - (uintptr_t)symtab) / sizeof(Elf64_Sym);
    unresolved_syms = std::vector<std::pair<std::string, uint64_t>>();
    
    for (int i = 0; i < numsyms; i++)
    {
        char* demangled = cplus_demangle(strtab + symtab[i].st_name, 0);
        printf("%s %llx %x\n", demangled, symtab[i].st_value, symtab[i].st_shndx);
        
        if (symtab[i].st_shndx == 0 && demangled)
        {
            unresolved_syms.push_back(std::pair(std::string(demangled), NRO + symtab[i].st_value));
        }
        else if (symtab[i].st_shndx && demangled)
        {
            resolved_syms[std::string(demangled)] = NRO + symtab[i].st_value;
        }
        free(demangled);
    }*/
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
}

void uc_print_regs(uc_engine *uc)
{
    uint64_t x0, x1, x2, x3, x4, x5 ,x6 ,x7, x8;
    uint64_t x9, x10, x11, x12, x13, x14, x15, x16;
    uint64_t x17, x18, x19, x20, x21, x22, x23, x24;
    uint64_t x25, x26, x27, x28, fp, lr, sp, pc;
    
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

    printf("Register dump:\n");
    printf("x0  %16.16llx ", x0);
    printf("x1  %16.16llx ", x1);
    printf("x2  %16.16llx ", x2);
    printf("x3  %16.16llx ", x3);
    printf("\n");
    printf("x4  %16.16llx ", x4);
    printf("x5  %16.16llx ", x5);
    printf("x6  %16.16llx ", x6);
    printf("x7  %16.16llx ", x7);
    printf("\n");
    printf("x8  %16.16llx ", x8);
    printf("x9  %16.16llx ", x9);
    printf("x10 %16.16llx ", x10);
    printf("x11 %16.16llx ", x11);
    printf("\n");
    printf("x12 %16.16llx ", x12);
    printf("x13 %16.16llx ", x13);
    printf("x14 %16.16llx ", x14);
    printf("x15 %16.16llx ", x15);
    printf("\n");
    printf("x16 %16.16llx ", x16);
    printf("x17 %16.16llx ", x17);
    printf("x18 %16.16llx ", x18);
    printf("x19 %16.16llx ", x19);
    printf("\n");
    printf("x20 %16.16llx ", x20);
    printf("x21 %16.16llx ", x21);
    printf("x22 %16.16llx ", x22);
    printf("x23 %16.16llx ", x23);
    printf("\n");
    printf("x24 %16.16llx ", x24);
    printf("x25 %16.16llx ", x25);
    printf("x26 %16.16llx ", x26);
    printf("x27 %16.16llx ", x27);
    printf("\n");
    printf("x28 %16.16llx ", x28);
    printf("\n");
    printf("fp  %16.16llx ", fp);
    printf("lr  %16.16llx ", lr);
    printf("sp  %16.16llx ", sp);
    printf("pc  %16.16llx ", pc);
    
    
    printf("\n");
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    static uint64_t last_pc[2];

    if (last_pc[0] == address && last_pc[0] == last_pc[1] && !uc_quit)
    {
        printf(">>> Hang at 0x%" PRIx64 " ?\n", address);
        uc_quit = true;
    }

    if (trace_code && !uc_quit)
    {
        //printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);
        //uc_print_regs(uc);
    }
    
    last_pc[1] = last_pc[0];
    last_pc[0] = address;
}

static void hook_import(uc_engine *uc, uint64_t address, uint32_t size, void* data)
{
    std::string name = unresolved_syms_rev[address];
    //printf(">>> Import '%s' at %llx, size %x\n", name.c_str(), address, size);
    
    uint64_t args[8];
    uc_reg_read(uc, UC_ARM64_REG_X0, &args[0]);
    uc_reg_read(uc, UC_ARM64_REG_X1, &args[1]);
    uc_reg_read(uc, UC_ARM64_REG_X2, &args[2]);
    uc_reg_read(uc, UC_ARM64_REG_X3, &args[3]);
    uc_reg_read(uc, UC_ARM64_REG_X4, &args[4]);
    uc_reg_read(uc, UC_ARM64_REG_X5, &args[5]);
    uc_reg_read(uc, UC_ARM64_REG_X6, &args[6]);
    uc_reg_read(uc, UC_ARM64_REG_X7, &args[7]);
    
    if (name == "operator new")
    {
        uint64_t alloc = args[0];
        args[0] = HEAP + heap_size;
        
        heap_size += alloc;
    }
    else if (name == "lib::L2CAgent::sv_set_function_hash")
    {
        printf("lib::L2CAgent::sv_set_function_hash(0x%llx, 0x%llx, 0x%llx)\n", args[0], args[1], args[2]);
    }
    
    uc_reg_write(uc, UC_ARM64_REG_X0, &args[0]);
    uc_reg_write(uc, UC_ARM64_REG_X1, &args[1]);
    uc_reg_write(uc, UC_ARM64_REG_X2, &args[2]);
    uc_reg_write(uc, UC_ARM64_REG_X3, &args[3]);
    uc_reg_write(uc, UC_ARM64_REG_X4, &args[4]);
    uc_reg_write(uc, UC_ARM64_REG_X5, &args[5]);
    uc_reg_write(uc, UC_ARM64_REG_X6, &args[6]);
    uc_reg_write(uc, UC_ARM64_REG_X7, &args[7]);
    
    uint64_t lr;
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
    uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
}

static void hook_memrw(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void* user_data)
{
    switch(type) 
    {
        default: break;
        case UC_MEM_READ:
                 printf(">>> Memory is being READ at 0x%"PRIx64 ", data size = %u\n", addr, size);
                 break;
        case UC_MEM_WRITE:
                 printf(">>> Memory is being WRITE at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", addr, size, value);
                 break;
    }
    return;
}

// callback for tracing memory access (READ or WRITE)
static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
    switch(type) {
        default:
            // return false to indicate we want to stop emulation
            return false;
        case UC_MEM_READ_UNMAPPED:
            printf(">>> Missing memory is being READ at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", address, size, value);
            //uc_print_regs(uc);
            
            return false;
        case UC_MEM_WRITE_UNMAPPED:        
            printf(">>> Missing memory is being WRITE at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", address, size, value);
            //uc_print_regs(uc);
            
            return true;
        case UC_ERR_FETCH_UNMAPPED:
            printf(">>> Missing memory is being EXEC at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", address, size, value);
            return false;
        case UC_ERR_EXCEPTION:
            printf(">>> Exception\n");
            return false;
    }
}


static void uc_reg_init(uc_engine *uc, int core)
{
    uint64_t zero = 0;
    for (int i = UC_ARM64_REG_PC+1; i < UC_ARM64_REG_ENDING; i++)
    {
        zero = 0x0;
        uc_reg_read(uc, i, &zero);
    }
    
    uint32_t x;
    uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &x);
    x |= 0x300000; // set FPEN bit
    uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &x);
}

static uc_err uc_init(uc_engine **uc, int core)
{
    uc_err err;
    uc_hook trace1, trace2, trace3;

    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        return err;
    }
    
    uc_reg_init(*uc, core);

    // import hooks    
    for (auto pair : unresolved_syms)
    {
        uc_hook trace;
        uc_hook_add(*uc, &trace, UC_HOOK_CODE, (void*)hook_import, NULL, pair.second, pair.second);
    }
    
    // granular hooks
    uc_hook_add(*uc, &trace1, UC_HOOK_CODE, (void*)hook_code, NULL, 1, 0);
    uc_hook_add(*uc, &trace2, UC_HOOK_MEM_UNMAPPED, (void*)hook_mem_invalid, NULL, 1, 0);
    //uc_hook_add(*uc, &trace3, UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, (void*)hook_memrw, NULL, 1, 0);
}

static uc_err uc_core_run_slice(uc_engine *uc)
{
    uc_err err;
    uint64_t pc;
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
    
    int instrs = 0x10000;
    
    // uc cores cannot share mappings, otherwise cores can flush
    // bad data, so just unmap after each slice has run
    //TODO proper mappings
    uc_mem_map_ptr(uc, NRO, NRO_SIZE, UC_PROT_ALL, nro);
    uc_mem_map_ptr(uc, HEAP, HEAP_SIZE, UC_PROT_ALL, heap);
    uc_mem_map_ptr(uc, IMPORTS, IMPORTS_SIZE, UC_PROT_ALL, imports);
    uc_mem_map_ptr(uc, STACK, STACK_SIZE, UC_PROT_ALL, stack); //TODO per-instance!
    
    err = uc_emu_start(uc, pc, 0, 0, instrs);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
        uc_quit = true;
    }
    
    uc_mem_unmap(uc, STACK, STACK_SIZE);
    uc_mem_unmap(uc, IMPORTS, IMPORTS_SIZE);
    uc_mem_unmap(uc, HEAP, HEAP_SIZE);
    uc_mem_unmap(uc, NRO, NRO_SIZE);
}

static void uc_run_stuff(uc_engine **cores, uint64_t start)
{
    uc_err err = UC_ERR_OK;
    uint64_t pc = start;
    uint64_t sp = STACK + STACK_SIZE;
    uint64_t x0, x1, x2, x3;
    
    //TODO turn these into speculative execution instances
    for (int i = 0; i < 4; i++)
    {
        uc_init(&cores[i], i);
    }

    cores_online[0] = true;
    uc_quit = false;
    
    x0 = hash40("wolf", 4); // Hash40
    x1 = 0xFFFE000000000000; // BattleObject
    x2 = 0xFFFD000000000000; // BattleObjectModuleAccessor
    x3 = 0xFFFC000000000000; // lua_state
    
    uc_reg_write(cores[0], UC_ARM64_REG_PC, &pc);
    uc_reg_write(cores[0], UC_ARM64_REG_SP, &sp);
    uc_reg_write(cores[0], UC_ARM64_REG_X0, &x0);
    uc_reg_write(cores[0], UC_ARM64_REG_X1, &x1);
    uc_reg_write(cores[0], UC_ARM64_REG_X2, &x2);
    uc_reg_write(cores[0], UC_ARM64_REG_X3, &x3);
    
    uint64_t vbar;

    while (!err && !uc_quit)
    {
        for (int i = 0; i < 4; i++)
        {
            if (!cores_online[i]) break;
            if (uc_quit) break;

            err = uc_core_run_slice(cores[i]);
            if (err) break;
        }
        if (uc_quit) break;
        
        
    }

    printf(">>> Emulation done. Below is the CPU contexts\n");
    
    for (int i = 0; i < 1; i++)
    {
        //printf("Core %u:\n", i);
        uc_print_regs(cores[i]);
    }
    
    for (int i = 0; i < 4; i++)
    {
        uc_close(cores[i]);
    }
}

static void mem_init()
{
    // map and read memory
    nro = malloc(NRO_SIZE);
    stack = malloc(STACK_SIZE);
    heap = malloc(HEAP_SIZE);
    imports = malloc(IMPORTS_SIZE);

    FILE* f_nro = fopen("lua2cpp_wolf.nro", "rb");
    fread(nro, NRO_SIZE, 1, f_nro);
    fclose(f_nro);
    
    nro_assignsyms(nro);
    nro_relocate(nro);
    
    // Write in constants
    memcpy(unresolved_syms["phx::detail::CRC32Table::table_"] - IMPORTS + imports, crc32_tab, sizeof(crc32_tab));
}

int main(int argc, char **argv, char **envp)
{
    mem_init();

    //TODO read syms
    printf("Running lua2cpp::create_agent_fighter_animcmd_effect_wolf...\n");
    uc_run_stuff(cores, resolved_syms["lua2cpp::create_agent_fighter_animcmd_effect_wolf"]);
    printf("Running lua2cpp::create_agent_fighter_animcmd_expression_wolf...\n");
    uc_run_stuff(cores, resolved_syms["lua2cpp::create_agent_fighter_animcmd_expression_wolf"]);
    printf("Running lua2cpp::create_agent_fighter_animcmd_game_wolf...\n");
    uc_run_stuff(cores, resolved_syms["lua2cpp::create_agent_fighter_animcmd_game_wolf"]);
    printf("Running lua2cpp::create_agent_fighter_animcmd_sound_wolf...\n");
    uc_run_stuff(cores, resolved_syms["lua2cpp::create_agent_fighter_animcmd_sound_wolf"]);

    return 0;
}
