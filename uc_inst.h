#ifndef UC_INST_H
#define UC_INST_H

#include "main.h"

#include <vector>
#include <deque>
#include <map>
#include "logging.h"

// memory addresses for different segments
#define NRO 0x100000000
#define NRO_SIZE (0x880000)

#define IMPORTS 0xEEEE000000000000
#define IMPORTS_SIZE (0x100000)

#define HEAP 0xBBBB000000000000
#define HEAP_SIZE (0x200000)

#define STACK 0xFFFF000000000000
#define STACK_SIZE (0x100000)
#define STACK_END (STACK + STACK_SIZE)

#define MAGIC_IMPORT 0xF00F1B015
#define INSTR_RET 0xD65F03C0

#define REG_HISTORY_LIMIT 10
#define JUMP_HISTORY_LIMIT 10

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
    
    std::vector<uc_inst*> forks;
    uc_inst* parent;
    uint64_t start_addr = 0;
    uint64_t end_addr = 0;
    uint64_t outputted_tokens = 0;
    
    bool slow;
    bool temp_simple = false;
    bool uc_term;
    int instance_id;
    
    std::vector<uint64_t> block_stack;
    std::deque<uc_reg_state> reg_history;
    std::deque<uint64_t> jump_history;

public:
    std::vector<L2CValue> lua_stack;
    std::map<uint64_t, L2CValue*> lua_active_vars;

    uc_inst(std::string nrofile)
    {
        // map and read memory
        nro = malloc(NRO_SIZE);
        stack = malloc(STACK_SIZE);
        heap = malloc(HEAP_SIZE);
        imports = malloc(IMPORTS_SIZE);
        
        parent = nullptr;
        uc_term = false;

        FILE* f_nro = fopen(nrofile.c_str(), "rb");
        fread(nro, NRO_SIZE, 1, f_nro);
        fclose(f_nro);
        
        nro_assignsyms(nro);
        nro_relocate(nro);
        
        // Write in constants
        memcpy(uc_ptr_to_real_ptr(unresolved_syms["phx::detail::CRC32Table::table_"]), crc32_tab, sizeof(crc32_tab));
        
        uc_init();
        instance_id = instance_id_cnt++;
    }
    
    uc_inst(uc_inst* to_clone)
    {
        // map and read memory
        nro = to_clone->nro;
        stack = malloc(STACK_SIZE);
        heap = malloc(HEAP_SIZE);
        imports = malloc(IMPORTS_SIZE);
        
        parent = to_clone;
        uc_term = false;
        
        memcpy(stack, to_clone->stack, STACK_SIZE);
        memcpy(heap, to_clone->heap, HEAP_SIZE);
        memcpy(imports, to_clone->imports, IMPORTS_SIZE);
        heap_size = to_clone->heap_size;
        lua_stack = to_clone->lua_stack;
        lua_active_vars = to_clone->lua_active_vars;
        block_stack = to_clone->block_stack;
        slow = to_clone->slow;
        temp_simple = to_clone->temp_simple;
        reg_history = to_clone->reg_history;
        jump_history = to_clone->jump_history;
        
        // Write in constants
        memcpy(unresolved_syms["phx::detail::CRC32Table::table_"] - IMPORTS + imports, crc32_tab, sizeof(crc32_tab));
        
        uc_init();
        instance_id = instance_id_cnt++;
        
        uc_reg_state regs;
        uc_read_reg_state(to_clone->uc, &regs);

        if (regs.pc == MAGIC_IMPORT)
        {
            regs.pc = regs.lr;
            pop_block(true);
        }

        uc_write_reg_state(uc, &regs);
    }
    
    ~uc_inst()
    {
        for (auto fork : forks)
        {
            if (fork) delete fork;
        }
        forks.clear();
        
        uc_mem_unmap(uc, STACK, STACK_SIZE);
        uc_mem_unmap(uc, IMPORTS, IMPORTS_SIZE);
        uc_mem_unmap(uc, HEAP, HEAP_SIZE);
        uc_mem_unmap(uc, NRO, NRO_SIZE);
        uc_close(uc);
        
        free(imports);
        free(heap);
        free(stack);
        
        if (!has_parent())
            free(nro);
        
        nro = nullptr;
        stack = nullptr;
        heap = nullptr;
        imports = nullptr;
    }
    
    void fork_complete()
    {
        for (auto fork : forks)
        {
            if (fork && !fork->is_term() && !fork->get_start_addr())
                printf_warn("Instance Id %u: Fork Instance Id %u never finished diverge tests!\n", get_id(), fork->get_id());
        
            uc_err err = UC_ERR_OK;
            while (fork && !err && !fork->is_term())
            {
                err = fork->uc_run_slice();
            }
            
            fork->fork_complete();
            
            if (fork) delete fork;
        }
        forks.clear();
    }
    
    void fork_inst(bool independent = false)
    {
        if (is_term()) return;

        uc_inst* fork = new uc_inst(this);
        if (independent)
        {
            fork->set_start_addr(fork->get_pc());
            fork->set_end_addr(fork->get_lr());
        }

        printf_verbose("Instance Id %u forked to Instance Id %u, start=%llx, end=%llx\n", get_id(), fork->get_id(), fork->get_start_addr(), fork->get_end_addr());
        forks.push_back(fork);
    }
    
    void uc_reg_init()
    {
        uint32_t x;
        uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &x);
        x |= 0x300000; // set FPEN bit
        uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &x);
    }
    
    void add_import_hook(uint64_t addr)
    {
        uc_hook trace;
        uc_hook_add(uc, &trace, UC_HOOK_CODE, (void*)hook_import, this, addr, addr);
    }
    
    uc_err uc_init()
    {
        uc_err err;
        uc_hook trace1, trace2, trace3;

        err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
        if (err) {
            printf_error("Instance Id %u: Failed on uc_open() with error returned: %u (%s)\n",
                    get_id(), err, uc_strerror(err));
            return err;
        }
        
        uc_reg_init();

        // import hooks
        for (auto pair : unresolved_syms)
        {
            uc_hook trace;
            
            //printf("%" PRIx64 "\n", pair.second);
            
            uc_hook_add(uc, &trace, UC_HOOK_CODE, (void*)hook_import, this, pair.second, pair.second);
        }
        
        // granular hooks
        //uc_hook_add(uc, &trace1, UC_HOOK_CODE, (void*)hook_code, this, 1, 0);
        uc_hook_add(uc, &trace2, UC_HOOK_MEM_UNMAPPED, (void*)hook_mem_invalid, this, 1, 0);
        //uc_hook_add(uc, &trace3, UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, (void*)hook_memrw, this, 1, 0);
        
        uc_mem_map_ptr(uc, NRO, NRO_SIZE, UC_PROT_ALL, nro);
        uc_mem_map_ptr(uc, HEAP, HEAP_SIZE, UC_PROT_ALL, heap);
        uc_mem_map_ptr(uc, IMPORTS, IMPORTS_SIZE, UC_PROT_ALL, imports);
        uc_mem_map_ptr(uc, STACK, STACK_SIZE, UC_PROT_ALL, stack);
        
        return err;
    }
    
    uc_err uc_run_slice()
    {
        uc_err err;
        uint64_t start_pc, start_lr, start_sp;
        start_pc = get_pc();
        start_lr = get_lr();
        start_sp = get_sp();

        // Write to the register history before starting
        uc_reg_state regs;
        uc_read_reg_state(uc, &regs);
        reg_history.push_front(regs);
        if (reg_history.size() > REG_HISTORY_LIMIT)
        {
            reg_history.pop_back();
        }

        int instrs = (parent || slow) ? 1 : 0;
        
        if (start_pc == end_addr)
        {
            printf_info("Instance Id %u ran to completion.\n", get_id());
            uc_term = true;
            return err;
        }

        bool placed_fork = false;
        for (auto fork : forks)
        {
            if (fork->get_start_addr() || fork->is_term()) continue;

            if (fork->get_pc() != get_pc())
            {
                printf_verbose("Instance Id %u: Instance Id %u diverged from %" PRIx64 " to %" PRIx64 ", PC @ %" PRIx64 "\n", get_id(), fork->get_id(), reg_history[1].pc, fork->get_pc(), get_pc());
                
                fork->set_start_addr(fork->get_pc());
                
                // Branch instruction is the last instruction of that block
                blocks[get_current_block()].addr_end = reg_history[1].pc+4;

                L2C_Token token;
                token.pc = reg_history[1].pc;
                token.fork_hierarchy = get_fork_hierarchy();
                token.str = "DIV_FALSE";
                token.type = L2C_TokenType_Meta;
                token.args.push_back(get_pc());
                add_token_by_prio(this, get_current_block(), token);
                
                token.str = "DIV_TRUE";
                token.type = L2C_TokenType_Meta;
                token.args.clear();
                token.args.push_back(fork->get_pc());
                add_token_by_prio(this, get_current_block(), token);
                
                is_fork_origin[reg_history[1].pc] = true;
                
                if (get_current_block_type() == L2C_CodeBlockType_Fork)
                {
                    pop_block(true);
                    fork->pop_block(true);
                }

                push_block(L2C_CodeBlockType_Fork);
                fork->push_block(L2C_CodeBlockType_Fork);
                //print_blockchain();
                //fork->print_blockchain();
                
                // These usually happen with loops where there's one last if block at the end of a while
                // and the DIV_FALSE path just wraps back around
                if (blocks[get_current_block()].convergable_block(get_fork_hierarchy()))
                {
                    printf_debug("Instance Id %u: Found fork block convergence at %" PRIx64 ", outputted %u tokens\n", get_id(), start_pc, num_outputted_tokens());
                    uc_term = true;
                    return err;
                }
                
                placed_fork = true;
            }
            else
            {
                fork->uc_run_slice();
            }
        }
        
        if (slow && reg_history.size() > 2 
            && !placed_fork                               // it's not an if jump
            && reg_history[0].pc - reg_history[1].pc != 4 // but there's a jump...
            && reg_history[0].lr == reg_history[1].lr // but not a BL
            && reg_history[0].pc != reg_history[0].lr // and not a RET
            && (reg_history[0].pc >= NRO && reg_history[0].pc < NRO + NRO_SIZE) // and not an import call
            && reg_history[0].sp == reg_history[1].sp // and it's not some function prologue thing
            )
        {
            if (!is_fork_origin[reg_history[1].pc] && !is_basic_emu())
            {
                printf_verbose("Instance Id %u: Goto branch detected PC @ %" PRIx64 ", prev %" PRIx64 " lr %" PRIx64 "\n", get_id(), reg_history[0].pc, reg_history[1].pc, reg_history[0].lr);
                
                uint64_t goto_block = get_current_block();
                remove_block_matching_tokens(goto_block, blocks[goto_block].addr_end, "BLOCK_MERGE");
                remove_block_matching_tokens(goto_block, blocks[goto_block].addr_end, "SPLIT_BLOCK_MERGE");
                
                // Last block is done
                blocks[get_current_block()].addr_end = reg_history[1].pc+4;

                L2C_Token token;

                token.pc = reg_history[1].pc;
                token.fork_hierarchy = get_fork_hierarchy();
                token.str = "SUB_GOTO";
                token.type = L2C_TokenType_Branch;
                token.args.push_back(reg_history[0].pc);
                add_token_by_prio(this, goto_block, token);

                push_block(L2C_CodeBlockType_Goto);
                push_jump(reg_history[1].pc);
                
                if (get_start_addr() && blocks[reg_history[0].pc].convergable_block(get_fork_hierarchy()))
                {
                    printf_debug("Instance Id %u: Found goto block convergence at %" PRIx64 ", outputted %u tokens\n", get_id(), reg_history[0].pc, num_outputted_tokens());
                    uc_term = true;
                    return err;
                }
            }

            is_goto_dst[reg_history[0].pc] = true;
        }

        if (slow && blocks[start_pc].type != L2C_CodeBlockType_Invalid
            && start_pc != get_current_block())
        {
            printf_verbose("Instance Id %u: Crossed a block boundary at %" PRIx64 "! current_block=%" PRIx64 " creator=%i, type=%i\n", get_id(), start_pc, get_current_block(), blocks[start_pc].creator(), blocks[start_pc].type);

            // Last block is done
            blocks[get_current_block()].addr_end = start_pc;

            L2C_Token token;
            //TODO: move this back into the range?
            token.pc = blocks[get_current_block()].addr_end;
            token.fork_hierarchy = get_fork_hierarchy();
            token.str = "BLOCK_MERGE";
            token.type = L2C_TokenType_Meta;
            token.args.push_back(start_pc);
            add_token_by_prio(this, get_current_block(), token);

            if (get_current_block_type() == L2C_CodeBlockType_Fork)
                pop_block(true);

            if (get_start_addr() && blocks[start_pc].convergable_block(get_fork_hierarchy()))
            {
                //printf_debug("%s\n", blocks[start_pc].fork_hierarchy_str().c_str());
                printf_debug("Instance Id %u: Found block end convergence at %" PRIx64 ", outputted %u tokens\n", get_id(), start_pc, num_outputted_tokens());
                uc_term = true;
                return err;
            }

            push_block(L2C_CodeBlockType_Fork);
        }

        if (has_parent() && get_start_addr() && blocks[get_current_block()].convergable_block(get_fork_hierarchy()))
        {
            printf_debug("Instance Id %u: Found block convergence at %" PRIx64 ", outputted %u tokens\n", get_id(), start_pc, num_outputted_tokens());
            uc_term = true;
            return err;
        }

        // This instruction will run under this block
        if (slow && start_pc - blocks[get_current_block()].addr_end == 4)
            blocks[get_current_block()].addr_end = start_pc+4;
        
        //printf("Instance Id %u: block %llx-%llx, pc %llx, size %llx\n", get_id(), get_current_block(), blocks[get_current_block()].addr_end, start_pc, blocks[get_current_block()].size());

        err = uc_emu_start(uc, start_pc, 0, 0, instrs);
        if (err && !uc_term)
        {
            if (get_pc() == MAGIC_IMPORT)
            {
                err = UC_ERR_OK;
                set_pc(get_lr());

                pop_block();
                
                if (slow && get_pc() >= blocks[get_current_block()].addr_end)
                    blocks[get_current_block()].addr_end = get_pc();
            }
            else if (get_pc() == 0 && get_sp() == STACK_END)
            {
                printf_info("Instance Id %u ran to completion.\n", get_id());
                uc_term = true;
            }
            else
            {
                printf_error("Instance Id %u: Failed on uc_emu_start() with error returned: %u\n", get_id(), err);
                uc_print_regs(uc);
                uc_term = true;
                return err;
            }
        }

        if (!slow) return err;

        if (get_pc() && get_pc() - start_pc != 4 && get_lr() != start_lr)
        {
            printf_verbose("Instance Id %u: Branch detected PC @ %" PRIx64 ", prev %" PRIx64 " lr %" PRIx64 "\n", get_id(), get_pc(), start_pc, get_lr());
            L2C_Token token;
            
            token.pc = get_lr() ? get_lr() - 4 : 0;
            token.fork_hierarchy = get_fork_hierarchy();
            token.str = "SUB_BRANCH";
            token.type = L2C_TokenType_Branch;
            token.args.push_back(get_pc());
            if (!converge_points[token.pc])
            {
                add_token_by_prio(this, get_current_block(), token);
            }
            
            // Since subroutines can get called multiple times, blocks must be invalidated
            // to avoid convergence on forks
            invalidate_blocktree(this, get_pc());

            push_block();
            push_jump(start_pc);
        }
        
        if (*(uint32_t*)uc_ptr_to_real_ptr(start_pc) == INSTR_RET)
        {
            printf_verbose("Instance Id %u: RET detected at %" PRIx64 "\n", get_id(), start_pc);
            L2C_Token token;
            token.pc = start_pc;
            token.fork_hierarchy = get_fork_hierarchy();
            token.str = "SUB_RET";
            token.type = L2C_TokenType_Meta;
 
            uint64_t current = get_current_block();

            pop_block();
            
            //token.args.push_back(get_current_block());
            //token.args.push_back(get_pc());
            add_token_by_prio(this, current, token);
            
            if (start_pc+4 >= blocks[current].addr_end)
                blocks[current].addr_end = start_pc+4;
        }

        return err;
    }

    uint64_t uc_run_stuff(uint64_t start, bool run_slow, bool reset_heap_after, uint64_t x0 = 0, uint64_t x1 = 0, uint64_t x2 = 0, uint64_t x3 = 0)
    {
        uc_err err = UC_ERR_OK;
        uint64_t heap_size_start = heap_size;
        
        uint64_t outval = heap_alloc(0x10);

        uc_term = false;
        slow = run_slow;

        set_pc(start);
        set_sp(STACK_END);
        set_lr(0);
        uc_reg_write(uc, UC_ARM64_REG_X0, &x0);
        uc_reg_write(uc, UC_ARM64_REG_X1, &x1);
        uc_reg_write(uc, UC_ARM64_REG_X2, &x2);
        uc_reg_write(uc, UC_ARM64_REG_X3, &x3);
        
        //TODO: output value through x8 for some funcs
        uint64_t x8 = outval;
        uc_reg_write(uc, UC_ARM64_REG_X8, &x8);
        
        reg_history.clear();
        jump_history.clear();
        block_stack.clear();
        blocks.clear();
        parent = nullptr;
        forks.clear();
        instance_id_cnt = 1;
        outputted_tokens = 0;
        invalidate_blocktree(this, start);

        push_jump(start);
        blocks[0] = L2C_CodeBlock();
        blocks[start] = L2C_CodeBlock(start, L2C_CodeBlockType_Subroutine, get_fork_hierarchy());
        
        block_stack.push_back(0);
        block_stack.push_back(start);
        blocks[start].addr = start;
        blocks[start].type = get_current_block_type();
        start_addr = start;

        printf_info("Instance Id %u: Starting emulation of %" PRIx64 "\n", get_id(), start);
        while (!err && !uc_term)
        {
            err = uc_run_slice();
        }

        printf_info("Instance Id %u: Emulation done.\n", get_id());
        printf_verbose("Below is the CPU contexts:\n");
        uc_print_regs(uc);
        
        // Finish fork's work if it exists
        fork_complete();
        
        // We terminated in the middle of the function...
        if (get_sp() != STACK_END && err == UC_ERR_OK)
        {
            uint64_t nonreturning = get_current_block();
            while (get_current_block_type() != L2C_CodeBlockType_Subroutine)
            {
                pop_block();
                nonreturning = get_current_block();
                
                if (!nonreturning) break;
            }
        
            L2C_Token token;
            token.pc = blocks[nonreturning].addr_end;
            token.fork_hierarchy = get_fork_hierarchy();
            token.str = "NORETURN";
            token.type = L2C_TokenType_Meta;
            
            blocks[nonreturning].addr_end += 4;

            add_token_by_prio(this, nonreturning, token);
        }
        
        // Clean any loose strands and check for oddities
        clean_and_verify_blocks(start);
        
        printf_info("Instance Id %u: Emulation of %" PRIx64 " is complete.\n", get_id(), start);

        if (reset_heap_after)
            heap_size = heap_size_start;

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
        
        return nullptr;
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
    
    void set_pc(uint64_t pc)
    {
        uc_reg_write(uc, UC_ARM64_REG_PC, &pc);
    }
    
    void set_sp(uint64_t sp)
    {
        uc_reg_write(uc, UC_ARM64_REG_SP, &sp);
    }
    
    void set_lr(uint64_t lr)
    {
        uc_reg_write(uc, UC_ARM64_REG_LR, &lr);
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
    
    uint64_t get_lr()
    {
        uint64_t lr;
        uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
        return lr;
    }
    
    bool has_parent()
    {
        return parent != nullptr;
    }
    
    std::vector<int> get_fork_hierarchy()
    {
        std::vector<int> out;
 
        uc_inst* iter = this;
        while(iter)
        {
            out.push_back(iter->get_id());
            iter = iter->parent;
        }
        
        return out;
    }
    
    uint64_t get_jump_history(size_t depth = 0)
    {
        if (depth >= jump_history.size())
            return -1;

        return jump_history[depth];
    }
    
    void push_jump(uint64_t addr)
    {
        // Write to the register history before starting
        jump_history.push_front(addr);
        if (jump_history.size() > JUMP_HISTORY_LIMIT)
        {
            jump_history.pop_back();
        }
    }
    
    uint64_t get_current_block()
    {
        if (!slow) return 0;

        if (!block_stack.size()) 
        {
            printf_error("Instance Id %u: Bad cur block access!!\n", get_id());
            return -1;
        }
        
        return *(block_stack.end() - 1);
    }
    
    uint64_t get_last_block()
    {
        if (!slow) return 0;

        if (block_stack.size() <= 1) 
        {
            printf_error("Instance Id %u: Bad last block access!!\n", get_id());
            return -1;
        }

        return *(block_stack.end() - 2);
    }
    
    L2C_CodeBlockType get_current_block_type()
    {
        if (!slow) return L2C_CodeBlockType_Invalid;

        if (!block_stack.size()) 
        {
            printf_error("Instance Id %u: Bad cur block access!!\n", get_id());
            return L2C_CodeBlockType_Invalid;
        }
        
        return blocks[*(block_stack.end() - 1)].type;
    }
    
    L2C_CodeBlockType get_last_block_type()
    {
        if (!slow) return L2C_CodeBlockType_Invalid;

        if (block_stack.size() <= 1) 
        {
            printf_error("Instance Id %u: Bad last block access!!\n", get_id());
            return L2C_CodeBlockType_Invalid;
        }

        return blocks[*(block_stack.end() - 2)].type;
    }
    
    void push_block(L2C_CodeBlockType type = L2C_CodeBlockType_Subroutine, int backlog = 0)
    {
        if (!slow) return;

        uint64_t addr = backlog ? reg_history[backlog-1].pc : get_pc();
        block_stack.push_back(addr);

        L2C_CodeBlock new_block(addr, type, get_fork_hierarchy());
        printf_verbose("Instance Id %u: Push block %" PRIx64 ", type %s\n", get_id(), addr, new_block.typestr().c_str());
        
        for (auto& block_pair : blocks)
        {
            auto& block = block_pair.second;
            
            if (!block.addr) continue;

            //printf_verbose("%llx %llx-%llx\n", block_pair.first, block.addr, block.addr_end);
            
            if (addr == block.addr)
            {
                if (block.convergable_block(get_fork_hierarchy()))
                {
                    printf_verbose("Instance Id %u: Block's creator is greater, converging...?\n", get_id());
                    return;
                }

                printf_warn("Instance Id %u: Created block %" PRIx64 " resets existing block (prev %s, new %s)...\n", get_id(), addr, block.fork_hierarchy_str().c_str(), new_block.fork_hierarchy_str().c_str());
                break;
            }

            if (addr > block.addr && addr < block.addr_end)
            {
                uint64_t splitting_addr = block.addr;
                uint64_t splitting_addr_end = block.addr_end;

                printf_verbose("Instance Id %u: Created block has address conflicts!\n", get_id());
                printf_verbose("Instance Id %u: Existing, start=%" PRIx64 ", end=%" PRIx64 " Creating start=%" PRIx64 "\n", get_id(), splitting_addr, block.addr_end, addr);

                std::set<L2C_Token> to_split = tokens[splitting_addr];
                tokens[splitting_addr].clear();
                tokens[addr].clear();
  
                L2C_CodeBlock a, b;
                a = blocks[splitting_addr];
                a.addr = splitting_addr;
                a.addr_end = addr;

                b = blocks[splitting_addr];
                b.addr = addr;
                b.addr_end = splitting_addr_end;
                
                L2C_Token last_a_token;
                last_a_token.fork_hierarchy = get_fork_hierarchy();
                
                printf_verbose("Instance Id %u: Splitting... %llx-%llx %llx-%llx\n", get_id(), a.addr, a.addr_end, b.addr, b.addr_end);
                
                for (auto& token : to_split)
                {
                    if (token.pc >= a.addr && token.pc < a.addr_end)
                    {
                        tokens[splitting_addr].insert(token);
                        
                        last_a_token = token;
                        //printf("a ");
                        //token.print();
                    }
                    else if ((token.pc >= b.addr && token.pc < b.addr_end) 
                             || ((token.str == "BLOCK_MERGE" || token.str == "SPLIT_BLOCK_MERGE") 
                                && token.pc == b.addr_end))
                    {
                        tokens[addr].insert(token);
                        
                        //printf("b ");
                        //token.print();
                    }
                    else
                    {
                        printf_error("Instance Id %u: Failed to assign token at %" PRIx64 " during split!\n%s", get_id(), token.pc, token.to_string());
                    }
                }
                
                L2C_Token token;
                token.pc = a.addr_end;
                token.fork_hierarchy = last_a_token.fork_hierarchy;
                token.str = "SPLIT_BLOCK_MERGE";
                token.type = L2C_TokenType_Meta;
                token.args.push_back(b.addr);
                add_token_by_prio(this, a.addr, token);
                
                blocks[splitting_addr] = a;
                blocks[addr] = b;
                return;
            }
        }

        blocks[addr] = new_block;
    }
    
    void pop_block(bool single = false)
    {
        if (!slow) return;

        if (!block_stack.size()) 
        {
            printf_error("Instance Id %u: Bad block pop!!\n", get_id());
            return;
        }

        // Previous subroutine block should be discarded too
        if (!single
            && (get_current_block_type() == L2C_CodeBlockType_Goto
                || get_current_block_type() == L2C_CodeBlockType_Fork))
        {
            block_stack.pop_back();
        }

        if (!block_stack.size()) 
        {
            printf_error("Instance Id %u: Bad block pop!!\n", get_id());
            return;
        }

        block_stack.pop_back();
        printf_verbose("Instance Id %u: Block popped to %" PRIx64 "\n", get_id(), get_current_block());
    }
    
    void print_blockchain()
    {
        printf("Instance Id %u block chain:\n", get_id());
        
        int incr = 0;
        for (auto& b : block_stack)
        {
            printf("%u: addr %" PRIx64 ", type %s\n", incr++, blocks[b].addr, blocks[b].typestr().c_str());
        }
    }
    
    bool is_basic_emu()
    {
        return !slow || temp_simple;
    }
    
    uint64_t get_start_addr()
    {
        return start_addr;
    }
    
    void set_start_addr(uint64_t addr)
    {
        start_addr = addr;
    }
    
    uint64_t get_end_addr()
    {
        return end_addr;
    }
    
    void set_end_addr(uint64_t addr)
    {
        end_addr = addr;
    }
    
    uint64_t num_outputted_tokens()
    {
        return outputted_tokens;
    }
    
    void inc_outputted_tokens()
    {
        outputted_tokens++;
    }
};

#endif // UC_INST_H
