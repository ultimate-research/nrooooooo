#include "main.h"

#include <string.h>
#include <time.h>
#include <iostream>
#include <filesystem>
#include <list>
#include <elf.h>
#include <cxxabi.h>
#include <set>
#include "crc32.h"
#include "uc_inst.h"

struct L2C_Token
{
    uint64_t pc;
    int parent_id;
    std::string func;
    
    bool operator<(const L2C_Token& comp) const
    {
        return pc < comp.pc;
    }
};

int instance_id_cnt = 0;
std::map<std::string, uint64_t> unresolved_syms;
std::map<uint64_t, std::string> unresolved_syms_rev;
std::map<std::string, uint64_t> resolved_syms;
std::map<std::pair<uint64_t, uint64_t>, uint64_t> function_hashes;
std::vector<L2CValue> lua_stack;
std::map<uint64_t, L2CValue*> lua_active_vars;
std::set<L2C_Token> tokens;

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
    uint32_t dynamic;
};

void nro_assignsyms(void* base)
{
    const Elf64_Dyn* dyn = NULL;
    const Elf64_Rela* rela = NULL;
    const Elf64_Sym* symtab = NULL;
    const char* strtab = NULL;
    uint64_t relasz = 0;
    uint64_t numsyms = 0;
    
    if (syms_scanned) return;
    
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
        char* demangled = abi::__cxa_demangle(strtab + symtab[i].st_name, 0, 0, 0);

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
                char* demangled = abi::__cxa_demangle(name, 0, 0, 0);
                
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

void hook_code(uc_engine *uc, uint64_t address, uint32_t size, uc_inst* inst)
{
    static uint64_t last_pc[2];

    if (last_pc[0] == address && last_pc[0] == last_pc[1] && !inst->is_term())
    {
        printf(">>> Hang at 0x%" PRIx64 " ?\n", address);
        inst->terminate();
    }

    if (trace_code && !inst->is_term())
    {
        //printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);
        //uc_print_regs(uc);
    }
    
    last_pc[1] = last_pc[0];
    last_pc[0] = address;
}

void hook_import(uc_engine *uc, uint64_t address, uint32_t size, uc_inst* inst)
{
    uint64_t lr;
    std::string name = unresolved_syms_rev[address];
    
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
    printf(">>> Instance Id %u: Import '%s' from %llx, size %x\n", inst->get_id(), name.c_str(), lr - 4, size);
    
    // Add token
    L2C_Token token;
    token.pc = lr - 4;
    token.parent_id = inst->parent_id();
    token.func = name;
    if (tokens.find(token) != tokens.end() && inst->has_diverged())
    {
        printf(">>> Instance Id %u: Found convergence at %llx\n", inst->get_id(), lr - 4);
        inst->terminate();
        return;
    }

    tokens.insert(token);
    
    // Write out a magic PC val which will cause Unicorn to fault.
    // This allows for faster run time while there isn't a fork,
    // since more instructions can be ran at once.
    // Also helps to synchronize fork+parent PC vals when a fork
    // does happen.
    uint64_t magic = MAGIC_IMPORT;
    uc_reg_write(uc, UC_ARM64_REG_PC, &magic);
    
    uint64_t args[9];
    uc_reg_read(uc, UC_ARM64_REG_X0, &args[0]);
    uc_reg_read(uc, UC_ARM64_REG_X1, &args[1]);
    uc_reg_read(uc, UC_ARM64_REG_X2, &args[2]);
    uc_reg_read(uc, UC_ARM64_REG_X3, &args[3]);
    uc_reg_read(uc, UC_ARM64_REG_X4, &args[4]);
    uc_reg_read(uc, UC_ARM64_REG_X5, &args[5]);
    uc_reg_read(uc, UC_ARM64_REG_X6, &args[6]);
    uc_reg_read(uc, UC_ARM64_REG_X7, &args[7]);
    uc_reg_read(uc, UC_ARM64_REG_X8, &args[8]);
    
    if (name == "operator new(unsigned long)")
    {
        args[0] = inst->heap_alloc(args[1]);
    }
    else if (name == "lib::L2CAgent::sv_set_function_hash(void*, phx::Hash40)")
    {
        printf("Instance Id %u: lib::L2CAgent::sv_set_function_hash(0x%llx, 0x%llx, 0x%llx)\n", inst->get_id(), args[0], args[1], args[2]);
        
        function_hashes[std::pair<uint64_t, uint64_t>(args[0], args[2])] = args[1];
    }
    else if (name == "lib::utility::Variadic::get_format() const")
    {
        args[0] = 0;
    }
    else if (name == "lib::L2CAgent::clear_lua_stack()")
    {
        lua_stack = std::vector<L2CValue>();
    }
    else if (name == "app::sv_animcmd::is_excute(lua_State*)")
    {
        lua_stack.push_back(L2CValue(true)); //TODO fork?
    }
    else if (name == "lib::L2CAgent::pop_lua_stack(int)")
    {
        L2CValue* out = (L2CValue*)inst->uc_ptr_to_real_ptr(args[8]);
        
        *out = *(lua_stack.end() - 1);
        lua_stack.pop_back();
        
        lua_active_vars[args[8]] = out;
    }
    else if (name == "lib::L2CValue::~L2CValue()")
    {
        lua_active_vars[args[0]] = nullptr;
    }
    else if (name == "lib::L2CValue::operator bool() const")
    {
        L2CValue* val = lua_active_vars[args[0]];
        if (val)
        {
            args[0] = 0;//val->as_bool(); //TODO fork
            uc_reg_write(uc, UC_ARM64_REG_X0, &args[0]);    
            inst->fork_inst();
            
            args[0] = 1;
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
}

void hook_memrw(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, uc_inst* inst)
{
    switch(type) 
    {
        default: break;
        case UC_MEM_READ:
                 printf(">>> Instance Id %u: Memory is being READ at 0x%"PRIx64 ", data size = %u\n", inst->get_id(), addr, size);
                 break;
        case UC_MEM_WRITE:
                 printf(">>> Instance Id %u: Memory is being WRITE at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", inst->get_id(), addr, size, value);
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
            printf(">>> Instance Id %u: Missing memory is being READ at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", inst->get_id(), address, size, value);
            //uc_print_regs(uc);
            
            return false;
        case UC_MEM_WRITE_UNMAPPED:        
            printf(">>> Instance Id %u: Missing memory is being WRITE at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", inst->get_id(), address, size, value);
            //uc_print_regs(uc);
            
            return true;
        case UC_ERR_FETCH_UNMAPPED:
            printf(">>> Instance Id %u: Missing memory is being EXEC at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n", inst->get_id(), address, size, value);
            return false;
        case UC_ERR_EXCEPTION:
            if (address != MAGIC_IMPORT)
                printf(">>> Instance Id %u: Exception\n", inst->get_id());
            return false;
    }
}

int main(int argc, char **argv, char **envp)
{
    // lua2cpp::L2CFighterAnimcmdBase
    uint64_t animcmd_effect, animcmd_expression, animcmd_game, animcmd_sound;
    
    uint64_t x0, x1, x2, x3;
    x0 = hash40("wolf", 4); // Hash40
    x1 = 0xFFFE000000000000; // BattleObject
    x2 = 0xFFFD000000000000; // BattleObjectModuleAccessor
    x3 = 0xFFFC000000000000; // lua_state
    
    uc_inst inst = uc_inst();

    //TODO read syms
    printf("Running lua2cpp::create_agent_fighter_animcmd_effect_wolf...\n");
    animcmd_effect = inst.uc_run_stuff(resolved_syms["lua2cpp::create_agent_fighter_animcmd_effect_wolf(phx::Hash40, app::BattleObject*, app::BattleObjectModuleAccessor*, lua_State*)"], x0, x1, x2, x3);
    printf("Running lua2cpp::create_agent_fighter_animcmd_expression_wolf...\n");
    animcmd_expression = inst.uc_run_stuff(resolved_syms["lua2cpp::create_agent_fighter_animcmd_expression_wolf(phx::Hash40, app::BattleObject*, app::BattleObjectModuleAccessor*, lua_State*)"], x0, x1, x2, x3);
    printf("Running lua2cpp::create_agent_fighter_animcmd_game_wolf...\n");
    animcmd_game = inst.uc_run_stuff(resolved_syms["lua2cpp::create_agent_fighter_animcmd_game_wolf(phx::Hash40, app::BattleObject*, app::BattleObjectModuleAccessor*, lua_State*)"], x0, x1, x2, x3);
    printf("Running lua2cpp::create_agent_fighter_animcmd_sound_wolf...\n");
    animcmd_sound = inst.uc_run_stuff(resolved_syms["lua2cpp::create_agent_fighter_animcmd_sound_wolf(phx::Hash40, app::BattleObject*, app::BattleObjectModuleAccessor*, lua_State*)"], x0, x1, x2, x3);
    
    uint64_t l2cagent = inst.heap_alloc(0x1000);
    
    uint64_t some_func = function_hashes[std::pair<uint64_t, uint64_t>(animcmd_sound, 0x13a0c3d061)];
    inst.uc_run_stuff(some_func, l2cagent, 0xFFFA000000000000);

    return 0;
}
