#ifndef UC_INST_H
#define UC_INST_H

#include "main.h"

#include <vector>
#include <deque>
#include <map>
#include "logging.h"

// memory addresses for different segments
#define NRO 0x100000000
#define NRO_SIZE (0x2000000)

#define IMPORTS 0xEEEE000000000000
#define IMPORTS_SIZE (0x1000000)

#define HEAP 0xBBBB000000000000
#define HEAP_SIZE (0x800000)

#define STACK 0xFFFF000000000000
#define STACK_SIZE (0x100000)
#define STACK_END (STACK + STACK_SIZE)

#define MAGIC_IMPORT 0xF00F1B015
#define INSTR_RET 0xD65F03C0

#define REG_HISTORY_LIMIT 10
#define JUMP_HISTORY_LIMIT 10

enum CodeBlockType
{
    CodeBlockType_Invalid = 0,
    CodeBlockType_Subroutine,
    CodeBlockType_Goto,
    CodeBlockType_RetValSub,
    CodeBlockType_Fork,
};

struct CodeBlock
{
    CodeBlockType type;
    uint64_t addr;
    
    std::string typestr()
    {
        std::string typestr = "<unk>";
        if (type == CodeBlockType_Invalid)
        {
            typestr = "Invalid";
        }
        else if (type == CodeBlockType_Subroutine)
        {
            typestr = "Subroutine";
        }
        else if (type == CodeBlockType_Goto)
        {
            typestr = "Goto";
        }
        else if (type == CodeBlockType_RetValSub)
        {
            typestr = "RetValSub";
        }
        else if (type == CodeBlockType_Fork)
        {
            typestr = "Fork";
        }
        return typestr;
    }
};

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
    
    std::vector<CodeBlock> block_stack;
    std::deque<uc_reg_state> reg_history;
    std::deque<uint64_t> jump_history;

public:
    std::vector<L2CValue> lua_stack;
    std::map<uint64_t, L2CValue*> lua_active_vars;

    uc_inst()
    {
        // map and read memory
        nro = malloc(NRO_SIZE);
        stack = malloc(STACK_SIZE);
        heap = malloc(HEAP_SIZE);
        imports = malloc(IMPORTS_SIZE);
        
        parent = nullptr;
        uc_term = false;

        FILE* f_nro = fopen("lua2cpp_wolf.nro", "rb");
        fread(nro, NRO_SIZE, 1, f_nro);
        fclose(f_nro);
        
        nro_assignsyms(nro);
        nro_relocate(nro);
        
        // Write in constants
        memcpy(imports + (unresolved_syms["phx::detail::CRC32Table::table_"] - IMPORTS), crc32_tab, sizeof(crc32_tab));
        
        uc_init();
        instance_id = instance_id_cnt++;
    }
    
    uc_inst(uc_inst* to_clone)
    {
        // map and read memory
        nro = malloc(NRO_SIZE);
        stack = malloc(STACK_SIZE);
        heap = malloc(HEAP_SIZE);
        imports = malloc(IMPORTS_SIZE);
        
        parent = to_clone;
        uc_term = false;
        
        memcpy(nro, to_clone->nro, NRO_SIZE);
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
            uc_err err = UC_ERR_OK;
            while (fork && !err && !fork->is_term())
            {
                err = fork->uc_run_slice();
            }
            
            fork->fork_complete();
            
            if (fork) delete fork;
        }
        forks.clear();

        /*uc_err err = UC_ERR_OK;
        while (fork && !err && !fork->is_term())
        {
            err = fork->uc_run_slice();
        }
        
        if (fork) delete fork;
        fork = nullptr;
        
        fork_divergence = 0;*/
    }
    
    void fork_inst(bool independent = false)
    {
        //fork_complete();
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
            printf_error("Instance %u: Failed on uc_open() with error returned: %u (%s)\n",
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
        uint32_t exec_instr = 0;
        if (uc_ptr_to_real_ptr(get_pc()))
        {
            exec_instr = *(uint32_t*)uc_ptr_to_real_ptr(get_pc());
        }
        
        bool placed_fork = false;
        for (auto fork : forks)
        {
            if (fork->get_start_addr() || fork->is_term()) continue;

            if (fork->get_pc() != get_pc() /*&& get_pc() != MAGIC_IMPORT*/)
            {
                //fork_divergence = start_pc;
                printf_verbose("Instance Id %u: Fork %u diverged from %" PRIx64 " to %" PRIx64 ", PC @ %" PRIx64 "\n", get_id(), fork->get_id(), reg_history[1].pc, fork->get_pc(), get_pc());
                
                fork->set_start_addr(fork->get_pc());

                L2C_Token token;
                token.pc = reg_history[1].pc;
                token.fork_heirarchy = get_fork_heirarchy();
                token.block_depth = block_stack_depth();
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
                //converge_points[get_pc()] = true;
                
                if (get_current_block_type() == CodeBlockType_Fork)
                {
                    pop_block(true);
                    fork->pop_block(true);
                }

                push_block(CodeBlockType_Fork);
                fork->push_block(CodeBlockType_Fork);
                //print_blockchain();
                //fork->print_blockchain();
                
                placed_fork = true;
            }
            else
            {
                fork->uc_run_slice();
            }
        }
        
        if (start_pc == end_addr)
        {
            printf_info("Instance Id %u ran to completion.\n", get_id());
            uc_term = true;
            return err;
        }

        err = uc_emu_start(uc, start_pc, 0, 0, instrs);
        if (err && !uc_term)
        {
            if (get_pc() == MAGIC_IMPORT)
            {
                err = UC_ERR_OK;
                set_pc(get_lr());

                pop_block();
            }
            else if (get_pc() == 0 && get_sp() == STACK_END)
            {
                printf_info("Instance Id %u ran to completion.\n", get_id());
                uc_term = true;
                return err;
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
        
        if (reg_history.size() > 2 
            && reg_history[0].pc - reg_history[1].pc != 4 // there's a jump...
            && reg_history[0].lr == reg_history[1].lr // but not a BL
            && reg_history[0].pc != reg_history[0].lr // and not a RET
            && (reg_history[0].pc >= NRO && reg_history[0].pc < NRO + NRO_SIZE) // and not an import call
            && reg_history[0].sp == reg_history[1].sp // and it's not some function prologue thing
            //&& !(reg_history[0].pc == get_current_block() && get_current_block_type() == CodeBlockType_RetValSub) // not a RETBRANCH
            )
        {
            if (!is_fork_origin[reg_history[1].pc] && !is_basic_emu())
            {
                printf_verbose("Instance %u: Goto branch detected PC @ %" PRIx64 ", prev %" PRIx64 " lr %" PRIx64 "\n", get_id(), reg_history[0].pc, reg_history[1].pc, reg_history[0].lr);

                L2C_Token token;

                token.pc = reg_history[1].pc;
                token.fork_heirarchy = get_fork_heirarchy();
                token.block_depth = block_stack_depth();
                token.str = "SUB_GOTO";
                token.type = L2C_TokenType_Branch;
                token.args.push_back(reg_history[0].pc);
                add_token_by_prio(this, get_current_block(), token);

                //TODO: if the GOTO lands in the middle of a block, split it

                push_block(CodeBlockType_Goto, 1);
                push_jump(reg_history[1].pc);
            }
            
            if (is_goto_dst[reg_history[0].pc] && reg_history[0].pc < reg_history[1].pc)
            {
                printf_verbose("Instance %u: Definitely in a loop!\n", get_id());
                uc_term = true;
                
                if (is_basic_emu()) return err;
                
                std::vector<L2C_Token> to_erase;
                
                // Prune all extra tokens in the GOTO's block which exist in other blocks
                for(auto& pair : tokens)
                {
                    if (pair.first == reg_history[0].pc) continue;
                        
                    for (auto& tcomp : pair.second)
                    {
                        for(auto& t : tokens[reg_history[0].pc])
                        {
                            if (tcomp.pc == t.pc && t.str != "LOOPCONV")
                            {
                                printf_verbose("pruning %llx %s\n", t.pc, t.str.c_str());
                                to_erase.push_back(t);
                            }
                        }
                    }
                }

                for (auto& t : to_erase)
                {
                    tokens[reg_history[0].pc].erase(t);
                }
                
                // Find the next closest block that the GOTO block will proceed to
                uint64_t largest_token = 0;
                for(auto& t : tokens[reg_history[0].pc])
                {
                    if (t.pc > largest_token)
                    {
                        largest_token = t.pc;
                     }
                }
                
                

                L2C_Token token;

                token.pc = largest_token;
                token.fork_heirarchy = get_fork_heirarchy();
                token.block_depth = block_stack_depth();
                token.str = "LOOPCONV";
                token.type = L2C_TokenType_Meta;
                token.args.push_back(next_closest_block(reg_history[0].pc, largest_token));
                add_token_by_prio(this, get_current_block(), token);
                
                return err;
            }

            is_goto_dst[reg_history[0].pc] = true;
        }

        /*if (get_pc() - start_pc != 4 
            && get_lr() == start_lr 
            && get_pc() != get_lr() 
            && reg_history[1].sp < reg_history[0].sp)
        {
            printf_verbose("Instance %u: Retval branch detected PC @ %" PRIx64 ", prev %" PRIx64 " lr %" PRIx64 " prev % " PRIx64 "\n", get_id(), get_pc(), start_pc, get_lr(), start_lr);
            L2C_Token token;
            
            token.pc = start_pc;
            token.fork_heirarchy = get_fork_heirarchy();
            token.block_depth = block_stack_depth();
            token.str = "SUB_RETBRANCH";
            token.type = L2C_TokenType_Branch;
            token.args.push_back(get_pc());
            //if (!converge_points[token.pc] && !is_basic_emu())
            {
                add_token_by_prio(this, get_current_block(), token);
                //converge_points[token.pc] = true;
            }
            
            // Since subroutines can get called multiple times, blocks must be invalidated
            // to avoid convergence on forks
            invalidate_blocktree(this, get_pc());

            push_block(CodeBlockType_RetValSub);
            push_jump(start_pc);

            if (!is_basic_emu())
            {
                //fork_inst(true);
                //temp_simple = true;
            }
        }*/
        
        if (get_pc() - start_pc != 4 && get_lr() != start_lr)
        {
            printf_verbose("Instance %u: Branch detected PC @ %" PRIx64 ", prev %" PRIx64 " lr %" PRIx64 "\n", get_id(), get_pc(), start_pc, get_lr());
            L2C_Token token;
            
            token.pc = get_lr() ? get_lr() - 4 : 0;
            token.fork_heirarchy = get_fork_heirarchy();
            token.block_depth = block_stack_depth();
            token.str = "SUB_BRANCH";
            token.type = L2C_TokenType_Branch;
            token.args.push_back(get_pc());
            if (!converge_points[token.pc])
            {
                add_token_by_prio(this, get_current_block(), token);
                //converge_points[token.pc] = true;
            }
            
            // Since subroutines can get called multiple times, blocks must be invalidated
            // to avoid convergence on forks
            invalidate_blocktree(this, get_pc());

            push_block();
            push_jump(start_pc);
            
            if (!is_basic_emu())
            {
                //fork_inst(true);
                //temp_simple = true;
            }
        }
        
        if (exec_instr == INSTR_RET)
        {
            printf_verbose("Instance %u: ret detected\n", get_id());
            L2C_Token token;
            token.pc = start_pc;
            token.fork_heirarchy = get_fork_heirarchy();
            token.block_depth = block_stack_depth();
            token.str = "SUB_RET";
            token.type = L2C_TokenType_Meta;
 
            uint64_t current = get_current_block();

            pop_block();
            
            //token.args.push_back(get_current_block());
            //token.args.push_back(get_pc());
            add_token_by_prio(this, current, token);
        }

        return err;
    }

    uint64_t uc_run_stuff(uint64_t start, bool run_slow, uint64_t x0 = 0, uint64_t x1 = 0, uint64_t x2 = 0, uint64_t x3 = 0)
    {
        uc_err err = UC_ERR_OK;

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
        uint64_t x8 = 0;
        uc_reg_write(uc, UC_ARM64_REG_X8, &x8);
        
        reg_history.clear();
        jump_history.clear();
        block_stack.clear();
        parent = nullptr;
        //fork = nullptr;
        forks.clear();
        instance_id_cnt = 1;

        push_jump(start);
        block_stack.push_back({CodeBlockType_Invalid, 0});
        block_stack.push_back({CodeBlockType_Subroutine, start});
        blocks.insert(start);
        block_types[start] = get_current_block_type();
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
        clean_blocks(start);
        
        printf_info("Instance Id %u: Emulation of %" PRIx64 " is complete.\n", get_id(), start);

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
    
    std::vector<int> get_fork_heirarchy()
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
            printf("Instance Id %u: Bad cur block access!!\n", get_id());
            return -1;
        }
        
        return (block_stack.end() - 1)->addr;
    }
    
    uint64_t get_last_block()
    {
        if (!slow) return 0;

        if (block_stack.size() <= 1) 
        {
            printf("Instance Id %u: Bad last block access!!\n", get_id());
            return -1;
        }

        return (block_stack.end() - 2)->addr;
    }
    
    CodeBlockType get_current_block_type()
    {
        if (!slow) return CodeBlockType_Invalid;

        if (!block_stack.size()) 
        {
            printf("Instance Id %u: Bad cur block access!!\n", get_id());
            return CodeBlockType_Invalid;
        }
        
        return (block_stack.end() - 1)->type;
    }
    
    CodeBlockType get_last_block_type()
    {
        if (!slow) return CodeBlockType_Invalid;

        if (block_stack.size() <= 1) 
        {
            printf("Instance Id %u: Bad last block access!!\n", get_id());
            return CodeBlockType_Invalid;
        }

        return (block_stack.end() - 2)->type;
    }
    
    void push_block(CodeBlockType type = CodeBlockType_Subroutine, int backlog = 0)
    {
        if (!slow) return;

        CodeBlock b = {type, backlog ? reg_history[backlog-1].pc : get_pc()};
        //printf("Instance %u: Push block %" PRIx64 ", type %s\n", get_id(), b.addr, b.typestr().c_str());
        
        blocks.insert(b.addr);
        if (block_types[b.addr] == CodeBlockType_Invalid)
        {
            block_types[b.addr] = type;
        }
        block_stack.push_back(b);
    }
    
    void pop_block(bool single = false)
    {
        if (!slow) return;

        if (!block_stack.size()) 
        {
            printf("Instance Id %u: Bad block pop!!\n", get_id());
            return;
        }

        // Previous subroutine block should be discarded too
        if (!single
            && (get_current_block_type() == CodeBlockType_RetValSub
                || get_current_block_type() == CodeBlockType_Goto
                || get_current_block_type() == CodeBlockType_Fork))
        {
            block_stack.pop_back();
        }

        if (!block_stack.size()) 
        {
            printf("Instance Id %u: Bad block pop!!\n", get_id());
            return;
        }

        block_stack.pop_back();
        //printf("Instance Id %u: Block popped to %" PRIx64 "\n", get_id(), get_current_block());
    }
    
    size_t block_stack_depth()
    {
        return block_stack.size();
    }
    
    void print_blockchain()
    {
        printf("Instance %u block chain:\n", get_id());
        
        int incr = 0;
        for (auto& b : block_stack)
        {
            printf("%u: addr %" PRIx64 ", type %s\n", incr++, b.addr, b.typestr().c_str());
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
