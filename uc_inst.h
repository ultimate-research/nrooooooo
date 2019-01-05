#ifndef UC_INST_H
#define UC_INST_H

#include "main.h"

// memory addresses for different segments
#define NRO 0x100000000
#define NRO_SIZE (0x2000000)

#define IMPORTS 0xEEEE000000000000
#define IMPORTS_SIZE (0x800000)

#define HEAP 0xBBBB000000000000
#define HEAP_SIZE (0x800000)

#define STACK 0xFFFF000000000000
#define STACK_SIZE (0x100000)
#define STACK_END (STACK + STACK_SIZE)

#define MAGIC_IMPORT 0xF00F1B015

class uc_inst
{
private:
    uc_engine* uc;
    uc_err err_last;
    void* nro;
    void* imports;
    void* heap;
    uint64_t heap_size = 0;
    void* stack;
    
    uc_inst* parent;
    uc_inst* fork;
    uint64_t fork_divergence = 0;
    
    bool uc_term;
    int instance_id;

public:
    uc_inst() : fork(nullptr), parent(nullptr), uc_term(false)
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
        
        uc_init();
        instance_id = instance_id_cnt++;
    }
    
    uc_inst(uc_inst* to_clone) : fork(nullptr), parent(to_clone), uc_term(false)
    {
        // map and read memory
        nro = malloc(NRO_SIZE);
        stack = malloc(STACK_SIZE);
        heap = malloc(HEAP_SIZE);
        imports = malloc(IMPORTS_SIZE);
        
        memcpy(nro, to_clone->nro, NRO_SIZE);
        memcpy(stack, to_clone->stack, NRO_SIZE);
        memcpy(heap, to_clone->heap, NRO_SIZE);
        memcpy(imports, to_clone->imports, NRO_SIZE);
        heap_size = to_clone->heap_size;
        
        // Write in constants
        memcpy(unresolved_syms["phx::detail::CRC32Table::table_"] - IMPORTS + imports, crc32_tab, sizeof(crc32_tab));
        
        uc_init();
        instance_id = instance_id_cnt++;
        
        uc_reg_state regs;
        uc_read_reg_state(to_clone->uc, &regs);

        if (regs.pc == MAGIC_IMPORT)
        {
            regs.pc = regs.lr;
        }

        uc_write_reg_state(uc, &regs);
    }
    
    ~uc_inst()
    {
        if (fork) delete fork;
        fork = nullptr;
        
        uc_mem_unmap(uc, STACK, STACK_SIZE);
        uc_mem_unmap(uc, IMPORTS, IMPORTS_SIZE);
        uc_mem_unmap(uc, HEAP, HEAP_SIZE);
        uc_mem_unmap(uc, NRO, NRO_SIZE);
        uc_close(uc);
        
        free(imports);
        free(heap);
        free(stack);
        free(nro);
    }
    
    void fork_complete()
    {
        uc_err err = UC_ERR_OK;
        while (fork && !err && !fork->is_term())
        {
            err = fork->uc_run_slice();
        }
        
        if (fork) delete fork;
        fork = nullptr;
    }
    
    void fork_inst()
    {
        fork_complete();
        fork = new uc_inst(this);
        
        
    }
    
    void uc_reg_init()
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
    
    uc_err uc_init()
    {
        uc_err err;
        uc_hook trace1, trace2, trace3;

        err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
        if (err) {
            printf("Instance %u: Failed on uc_open() with error returned: %u (%s)\n",
                    instance_id, err, uc_strerror(err));
            return err;
        }
        
        uc_reg_init();

        // import hooks    
        for (auto pair : unresolved_syms)
        {
            uc_hook trace;
            uc_hook_add(uc, &trace, UC_HOOK_CODE, (void*)hook_import, this, pair.second, pair.second);
        }
        
        // granular hooks
        uc_hook_add(uc, &trace1, UC_HOOK_CODE, (void*)hook_code, this, 1, 0);
        uc_hook_add(uc, &trace2, UC_HOOK_MEM_UNMAPPED, (void*)hook_mem_invalid, this, 1, 0);
        //uc_hook_add(uc, &trace3, UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, (void*)hook_memrw, this, 1, 0);
        
        uc_mem_map_ptr(uc, NRO, NRO_SIZE, UC_PROT_ALL, nro);
        uc_mem_map_ptr(uc, HEAP, HEAP_SIZE, UC_PROT_ALL, heap);
        uc_mem_map_ptr(uc, IMPORTS, IMPORTS_SIZE, UC_PROT_ALL, imports);
        uc_mem_map_ptr(uc, STACK, STACK_SIZE, UC_PROT_ALL, stack);
    }
    
    uc_err uc_run_slice()
    {
        uc_err err;
        uint64_t pc;
        uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
        
        int instrs = (fork || parent) ? 1 : 0x100;

        if (fork && !fork->is_term())
            fork->uc_run_slice();

        err = uc_emu_start(uc, pc, 0, 0, instrs);
        if (err && !uc_term)
        {
            if (get_pc() == MAGIC_IMPORT)
            {
                uint64_t lr;
                uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
                uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
                err = UC_ERR_OK;
                
                pc = lr;
            }
            else if (get_pc() == 0 && get_sp() == STACK_END)
            {
                printf("Instance Id %u ran to completion.\n", instance_id);
                uc_term = true;
                return err;
            }
            else
            {
                printf("Instance Id %u: Failed on uc_emu_start() with error returned: %u\n", instance_id, err);
                uc_term = true;
                return err;
            }
        }
        
        if (fork && !fork->is_term())
        {
            // Check when fork is diverging
            if (!fork_divergence && fork->get_pc() != get_pc())
            {
                fork_divergence = pc;
                printf("Instance Id %u: Fork %u diverged from %llx to %llx, PC @ %llx\n", instance_id, fork->get_id(), pc, fork->get_pc(), get_pc());
            }
        }

        return err;
    }

    uint64_t uc_run_stuff(uint64_t start, uint64_t x0 = 0, uint64_t x1 = 0, uint64_t x2 = 0, uint64_t x3 = 0)
    {
        uc_err err = UC_ERR_OK;
        uint64_t pc = start;
        uint64_t sp = STACK_END;

        uc_term = false;

        uc_reg_write(uc, UC_ARM64_REG_PC, &pc);
        uc_reg_write(uc, UC_ARM64_REG_SP, &sp);
        uc_reg_write(uc, UC_ARM64_REG_X0, &x0);
        uc_reg_write(uc, UC_ARM64_REG_X1, &x1);
        uc_reg_write(uc, UC_ARM64_REG_X2, &x2);
        uc_reg_write(uc, UC_ARM64_REG_X3, &x3);
        
        uint64_t vbar;

        while (!err && !uc_term)
        {
            err = uc_run_slice();
        }

        printf(">>> Instance Id %u: Emulation done. Below is the CPU contexts\n", instance_id);
        uc_print_regs(uc);
        
        // Finish fork's work if it exists
        fork_complete();
        
        // Result
        uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
        
        return x0;
    }
    
    void* uc_ptr_to_real_ptr(uint64_t ptr)
    {
        if (ptr >= NRO && ptr < NRO + NRO_SIZE)
        {
            return (nro + ptr - NRO);
        }
        else if (ptr >= IMPORTS && ptr < IMPORTS + IMPORTS_SIZE)
        {
            return (imports + ptr - IMPORTS);
        }
        else if (ptr >= HEAP && ptr < HEAP + HEAP_SIZE)
        {
            return (heap + ptr - HEAP);
        }
        else if (ptr >= STACK && ptr < STACK_END)
        {
            return (stack + ptr - STACK);
        }
    }
    
    uint64_t heap_alloc(uint32_t size)
    {
        uint64_t retval = HEAP + heap_size;
        heap_size += size;
        
        return retval;
    }
    
    bool is_term()
    {
        return uc_term;
    }
    
    void terminate()
    {
        uc_term = true;
    }
    
    int get_id()
    {
        return instance_id;
    }
    
    int parent_id()
    {
        if (!parent) return -1;
        return parent->get_id();
    }
    
    uint64_t get_pc()
    {
        uint64_t pc;
        uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
        return pc;
    }
    
    uint64_t get_sp()
    {
        uint64_t sp;
        uc_reg_read(uc, UC_ARM64_REG_SP, &sp);
        return sp;
    }
    
    bool has_diverged()
    {
        if (parent && parent->fork_divergence)
            return true;

        return fork_divergence;
    }
};

#endif // UC_INST_H
