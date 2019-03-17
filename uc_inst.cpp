#include "uc_inst.h"

#include "uc_impl.h"
#include "clustermanager.h"

#include <atomic>
#include <thread>
#include <chrono>

std::atomic<int> uc_insts_active;
std::atomic<uint64_t> uc_memory_use = 0;

void uc_res_wait(int id)
{
    while (uc_memory_use > MAX_UC_MEM)
    {
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(1s);

        printf_warn("Instance Id %u: Waiting for memory use to lower (%" PRIx64 ", %u; MAX %" PRIx64 ")...\n", id, uc_memory_use.load(), uc_insts_active.load(), MAX_UC_MEM);
    }
}

EmuInstance::EmuInstance(ClusterManager* parent_cluster)
{
    cluster = parent_cluster;
    instance_id = cluster->create_id();
    
    uc_res_wait(get_id());
    
    // map and read memory
    
    nro = cluster->get_nro_mem();
    stack = malloc(STACK_SIZE);
    heap = malloc(HEAP_SIZE);
    imports = cluster->get_import_mem();
    
    parent = nullptr;
    uc_term = false;

    uc_insts_active++;
    uc_memory_use += STACK_SIZE + HEAP_SIZE;
}

EmuInstance::EmuInstance(ClusterManager* parent_cluster, EmuInstance* to_clone, EmuInstance* parent)
{
    cluster = parent_cluster;
    instance_id = cluster->create_id();
    
    uc_res_wait(get_id());

    // map and read memory
    nro = cluster->get_nro_mem();
    stack = malloc(STACK_SIZE);
    if (parent == nullptr && !cluster->get_heap_fixed())
        heap = malloc(HEAP_SIZE);
    else
        heap = to_clone->heap;
    imports = cluster->get_import_mem();
    
    this->parent = parent;
    uc_term = false;

    memcpy(stack, to_clone->stack, STACK_SIZE);
    memcpy(heap, to_clone->heap, HEAP_SIZE);
    memcpy(imports, to_clone->imports, IMPORTS_SIZE);
    heap_size = to_clone->heap_size;
    lua_stack = to_clone->lua_stack;
    lua_active_vars = to_clone->lua_active_vars;
    block_stack = to_clone->block_stack;
    slow = to_clone->slow;
    reg_history = to_clone->reg_history;
    jump_history = to_clone->jump_history;
    regs_cur = to_clone->regs_cur;
    fork_addr = get_pc() - 4;

    uc_insts_active++;
    uc_memory_use += STACK_SIZE + HEAP_SIZE;
}

EmuInstance::~EmuInstance()
{
    for (auto fork : forks)
    {
        if (fork) delete fork;
    }
    forks.clear();
    
    if (!has_parent() && !cluster->get_heap_fixed())
        free(heap);
    free(stack);
    
    nro = nullptr;
    stack = nullptr;
    heap = nullptr;
    imports = nullptr;
    uc_insts_active--;
    
    uc_memory_use -= STACK_SIZE + HEAP_SIZE;
}

int EmuInstance::cluster_id()
{
    return cluster->get_id();
}

void EmuInstance::forks_complete()
{
    for (auto fork : forks)
    {
        if (!fork) continue;
        if (!fork->is_term() && !fork->get_start_addr())
            printf_warn("Instance Id %u: Fork Instance Id %u never finished diverge tests!\n", get_id(), fork->get_id());
    
        uc_err err = UC_ERR_OK;
        while (fork && !err && !fork->is_term())
        {
            regs_invalidate();
            err = fork->uc_run_slice();
            regs_flush();
        }
        
        fork->forks_complete();
        
        if (fork) delete fork;
    }
    forks.clear();
}

void EmuInstance::fork_inst()
{
    if (is_term() || watching_fork) return;

    regs_invalidate();
    EmuInstance* fork = new EmuInstance(cluster, this, this);
    fork->pop_block(true);
    regs_flush();

    printf_verbose("Instance Id %u forked to Instance Id %u, start=%llx, end=%llx\n", get_id(), fork->get_id(), fork->get_start_addr(), fork->get_end_addr());
    forks.push_back(fork);
    
    watching_fork = fork->get_id();
}

uc_err EmuInstance::uc_run_slice()
{
    uc_err err;
    uint64_t start_pc = 0, start_lr = 0, start_sp = 0;
    
    regs_flush();
    start_pc = get_pc();
    start_lr = get_lr();
    start_sp = get_sp();

    // Write to the register history before starting
    reg_history.push_front(regs_cur);
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
        if (!fork) continue;
        if (fork->get_start_addr() || fork->is_term()) continue;

        if (fork->get_pc() != get_pc())
        {
            printf_verbose("Instance Id %u: Instance Id %u diverged from %" PRIx64 " to %" PRIx64 ", PC @ %" PRIx64 "\n", get_id(), fork->get_id(), reg_history[1].pc, fork->get_pc(), get_pc());
            
            fork->set_start_addr(fork->get_pc());
            
            // Branch instruction is the last instruction of that block
            cluster->blocks[get_current_block()].addr_end = reg_history[1].pc+4;

            L2C_Token token;
            token.pc = reg_history[1].pc;
            token.fork_hierarchy = get_fork_hierarchy();
            token.str = "DIV_FALSE";
            token.type = L2C_TokenType_Meta;
            token.args.push_back(get_pc());
            token.args.push_back(fork->get_fork_addr());
            cluster->add_token_by_prio(get_current_block(), token);
            
            token.str = "DIV_TRUE";
            token.type = L2C_TokenType_Meta;
            token.args.clear();
            token.args.push_back(fork->get_pc());
            token.args.push_back(fork->get_fork_addr());
            cluster->add_token_by_prio(get_current_block(), token);
            
            cluster->set_fork_origin(reg_history[1].pc);
            
            if (get_current_block_type() == L2C_CodeBlockType_Fork || get_current_block_type() == L2C_CodeBlockType_Goto)
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
            if (cluster->convergable_block(get_current_block(), get_fork_hierarchy()))
            {
                printf_debug("Instance Id %u: Found fork block convergence at %" PRIx64 ", outputted %u tokens\n", get_id(), get_pc(), num_outputted_tokens());
                uc_term = true;
                return err;
            }

            if (cluster->convergable_block(fork->get_current_block(), fork->get_fork_hierarchy()))
            {
                printf_debug("Instance Id %u: Found fork block convergence at %" PRIx64 ", outputted %u tokens\n", fork->get_id(), fork->get_pc(), fork->num_outputted_tokens());
                fork->terminate();
            }
            
            placed_fork = true;
            watching_fork = 0;
        }
        else
        {
            regs_invalidate();
            fork->uc_run_slice();
            regs_flush();
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
        if (!cluster->is_fork_origin(reg_history[1].pc) && !is_basic_emu())
        {
            printf_verbose("Instance Id %u: Goto branch detected PC @ %" PRIx64 ", prev %" PRIx64 " lr %" PRIx64 "\n", get_id(), reg_history[0].pc, reg_history[1].pc, reg_history[0].lr);
            
            uint64_t goto_block = get_current_block();
            cluster->remove_block_matching_tokens(goto_block, cluster->blocks[goto_block].addr_end, "BLOCK_MERGE");
            cluster->remove_block_matching_tokens(goto_block, cluster->blocks[goto_block].addr_end, "SPLIT_BLOCK_MERGE");
            
            // Last block is done
            cluster->blocks[get_current_block()].addr_end = reg_history[1].pc+4;

            L2C_Token token;

            token.pc = reg_history[1].pc;
            token.fork_hierarchy = get_fork_hierarchy();
            token.str = "SUB_GOTO";
            token.type = L2C_TokenType_Branch;
            token.args.push_back(reg_history[0].pc);
            cluster->add_token_by_prio(goto_block, token);

            if (get_current_block_type() == L2C_CodeBlockType_Fork || get_current_block_type() == L2C_CodeBlockType_Goto)
            {
                pop_block(true);
            }
            push_block(L2C_CodeBlockType_Goto);
            push_jump(reg_history[1].pc);
            
            if (get_start_addr() && cluster->convergable_block(reg_history[0].pc, get_fork_hierarchy()))
            {
                printf_debug("Instance Id %u: Found goto block convergence at %" PRIx64 ", outputted %u tokens\n", get_id(), reg_history[0].pc, num_outputted_tokens());
                uc_term = true;
                return err;
            }
        }
    }

    if (slow && !placed_fork
        && cluster->blocks[start_pc].type != L2C_CodeBlockType_Invalid
        && start_pc != get_current_block()
        && get_start_addr() && !watching_fork)
    {
        printf_verbose("Instance Id %u: Crossed a block boundary at %" PRIx64 "! current_block=%" PRIx64 " creator=%i, type=%i\n", get_id(), start_pc, get_current_block(), cluster->blocks[start_pc].creator(), cluster->blocks[start_pc].type);

        // Last block is done
        cluster->blocks[get_current_block()].addr_end = start_pc;

        L2C_Token token;
        //TODO: move this back into the range?
        token.pc = cluster->blocks[get_current_block()].addr_end;
        token.fork_hierarchy = get_fork_hierarchy();
        token.str = "BLOCK_MERGE";
        token.type = L2C_TokenType_Meta;
        token.args.push_back(start_pc);
        if (!cluster->is_fork_origin(reg_history[1].pc))
        {
            uint64_t block = get_current_block();
            cluster->remove_block_matching_tokens(block, cluster->blocks[block].addr_end, "SPLIT_BLOCK_MERGE");
            cluster->add_token_by_prio(get_current_block(), token);
        }

        if (get_current_block_type() == L2C_CodeBlockType_Fork || get_current_block_type() == L2C_CodeBlockType_Goto)
            pop_block(true);

        if (get_start_addr() && cluster->convergable_block(start_pc, get_fork_hierarchy()))
        {
            //printf_debug("%s\n", cluster->blocks[start_pc].fork_hierarchy_str().c_str());
            printf_debug("Instance Id %u: Found block end convergence at %" PRIx64 ", outputted %u tokens\n", get_id(), start_pc, num_outputted_tokens());
            uc_term = true;
            return err;
        }

        push_block(L2C_CodeBlockType_Fork);
    }

    if (has_parent() && get_start_addr() && cluster->convergable_block(get_current_block(), get_fork_hierarchy()))
    {
        printf_debug("Instance Id %u: Found block convergence at %" PRIx64 ", outputted %u tokens\n", get_id(), start_pc, num_outputted_tokens());
        uc_term = true;
        return err;
    }

    // This instruction will run under this block
    if (slow && start_pc - cluster->blocks[get_current_block()].addr_end == 4)
        cluster->blocks[get_current_block()].addr_end = start_pc+4;
    
    //printf("Instance Id %u: block %llx-%llx, pc %llx, size %llx\n", get_id(), get_current_block(), cluster->blocks[get_current_block()].addr_end, start_pc, cluster->blocks[get_current_block()].size());

    cluster->set_running_inst(this);
    regs_flush();
    uc_mem_map_ptr(cluster->get_uc(), HEAP, HEAP_SIZE, UC_PROT_ALL, heap);
    uc_mem_map_ptr(cluster->get_uc(), STACK, STACK_SIZE, UC_PROT_ALL, stack);
    err = uc_emu_start(cluster->get_uc(), start_pc, 0, 0, instrs);
    uc_mem_unmap(cluster->get_uc(), STACK, STACK_SIZE);
    uc_mem_unmap(cluster->get_uc(), HEAP, HEAP_SIZE);
    regs_invalidate();
    
    //printf("Instance Id %u: block %llx-%llx, pc %llx, size %llx\n", get_id(), get_current_block(), cluster->blocks[get_current_block()].addr_end, get_pc(), cluster->blocks[get_current_block()].size());

    if (err && !uc_term)
    {
        if (get_pc() == MAGIC_IMPORT)
        {
            err = UC_ERR_OK;
            set_pc(get_lr());

            pop_block();
            
            if (slow && get_pc() > cluster->blocks[get_current_block()].addr_end && get_pc() - cluster->blocks[get_current_block()].addr_end == 4)
                cluster->blocks[get_current_block()].addr_end = get_pc();
        }
        else if (get_pc() == 0 && get_sp() == STACK_END)
        {
            printf_info("Instance Id %u ran to completion.\n", get_id());
            uc_term = true;
        }
        else
        {
            printf_error("Instance Id %u: Failed on uc_emu_start() with error returned: %u\n", get_id(), err);
            uc_print_regs(cluster->get_uc()); // use struct
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
        if (!cluster->converge_points[token.pc])
        {
            cluster->add_token_by_prio(get_current_block(), token);
        }
        
        // Since subroutines can get called multiple times, blocks must be invalidated
        // to avoid convergence on forks
        cluster->invalidate_blocktree(this, get_pc());

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

        //print_blockchain();
        pop_block();
        
        //token.args.push_back(get_current_block());
        //token.args.push_back(get_pc());
        cluster->add_token_by_prio(current, token);
        
        if (start_pc+4 >= cluster->blocks[current].addr_end)
            cluster->blocks[current].addr_end = start_pc+4;
    }

    return err;
}

uint64_t EmuInstance::execute(uint64_t start, bool run_slow, bool reset_heap_after, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3)
{
    uc_err err = UC_ERR_OK;
    uint64_t heap_size_start = heap_size;
    
    uint64_t outval = heap_alloc(0x10);

    uc_term = false;
    slow = run_slow;

    set_pc(start);
    set_sp(STACK_END);
    set_lr(0);
    regs_cur.x0 = x0;
    regs_cur.x1 = x1;
    regs_cur.x2 = x2;
    regs_cur.x3 = x3;
    
    //TODO: output value through x8 for some funcs
    uint64_t x8 = outval;
    regs_cur.x8 = x8;
    
    reg_history.clear();
    jump_history.clear();
    block_stack.clear();
    parent = nullptr;
    forks.clear();
    outputted_tokens = 0;
    cluster->invalidate_blocktree(this, start);

    push_jump(start);
    cluster->blocks[0] = L2C_CodeBlock();
    cluster->blocks[start] = L2C_CodeBlock(start, L2C_CodeBlockType_Subroutine, get_fork_hierarchy());
    
    block_stack.push_back(0);
    block_stack.push_back(start);
    cluster->blocks[start].addr = start;
    cluster->blocks[start].type = get_current_block_type();
    start_addr = start;

    printf_info("Instance Id %u: Starting emulation of %" PRIx64 "\n", get_id(), start);
    while (!err && !uc_term)
    {
        err = uc_run_slice();
    }

    printf_info("Instance Id %u: Emulation done.\n", get_id());
    printf_verbose("Below is the CPU contexts:\n");
    uc_print_regs(cluster->get_uc()); //TODO ehhhhh use struct
    
    // Finish fork's work if it exists
    forks_complete();
    
    // We terminated in the middle of the function...
    bool is_noreturn = false;
    if (get_sp() != STACK_END && err == UC_ERR_OK)
    {
        /*uint64_t nonreturning = get_current_block();
        while (get_current_block_type() != L2C_CodeBlockType_Subroutine)
        {
            pop_block();
            nonreturning = get_current_block();
            
            if (!nonreturning) break;
        }
    
        L2C_Token token;
        token.pc = cluster->blocks[nonreturning].addr_end;
        token.fork_hierarchy = get_fork_hierarchy();
        token.str = "NORETURN";
        token.type = L2C_TokenType_Meta;
        
        cluster->blocks[nonreturning].addr_end += 4;

        cluster->add_token_by_prio(nonreturning, token);*/
        is_noreturn = true;
    }
    
    // Clean any loose strands and check for oddities
    cluster->clean_and_verify_blocks(start, is_noreturn);
    
    printf_info("Instance Id %u: Emulation of %" PRIx64 " is complete.\n", get_id(), start);

    if (reset_heap_after)
        heap_size = heap_size_start;

    // Result
    x0 = regs_cur.x0;
    
    return x0;
}

void* EmuInstance::uc_ptr_to_real_ptr(uint64_t ptr)
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

uint64_t EmuInstance::heap_alloc(uint32_t size)
{
    uint64_t retval = HEAP + heap_size;
    heap_size += size;

    return retval;
}

bool EmuInstance::is_term()
{
    return uc_term;
}

void EmuInstance::terminate()
{
    uc_term = true;
}

int EmuInstance::get_id()
{
    return instance_id;
}

int EmuInstance::parent_id()
{
    if (!parent) return -1;
    return parent->get_id();
}

void EmuInstance::set_pc(uint64_t pc)
{
    regs_cur.pc = pc;
}

void EmuInstance::set_sp(uint64_t sp)
{
    regs_cur.sp = sp;
}

void EmuInstance::set_lr(uint64_t lr)
{
    regs_cur.lr = lr;
}

uint64_t EmuInstance::get_pc()
{
    return regs_cur.pc;
}

uint64_t EmuInstance::get_sp()
{
    return regs_cur.sp;
}

uint64_t EmuInstance::get_lr()
{
    return regs_cur.lr;
}

bool EmuInstance::has_parent()
{
    return parent != nullptr;
}

std::vector<int> EmuInstance::get_fork_hierarchy()
{
    std::vector<int> out;
 
    EmuInstance* iter = this;
    while(iter)
    {
        out.push_back(iter->get_id());
        iter = iter->parent;
    }
    
    return out;
}

uint64_t EmuInstance::get_jump_history(size_t depth)
{
    if (depth >= jump_history.size())
        return -1;

    return jump_history[depth];
}

void EmuInstance::push_jump(uint64_t addr)
{
    // Write to the register history before starting
    jump_history.push_front(addr);
    if (jump_history.size() > JUMP_HISTORY_LIMIT)
    {
        jump_history.pop_back();
    }
}

uint64_t EmuInstance::get_current_block()
{
    if (!slow) return 0;

    if (!block_stack.size()) 
    {
        printf_error("Instance Id %u: Bad cur block access!!\n", get_id());
        return -1;
    }
    
    return *(block_stack.end() - 1);
}

uint64_t EmuInstance::get_last_block()
{
    if (!slow) return 0;

    if (block_stack.size() <= 1) 
    {
        printf_error("Instance Id %u: Bad last block access!!\n", get_id());
        return -1;
    }

    return *(block_stack.end() - 2);
}

L2C_CodeBlockType EmuInstance::get_current_block_type()
{
    if (!slow) return L2C_CodeBlockType_Invalid;

    if (!block_stack.size()) 
    {
        printf_error("Instance Id %u: Bad cur block access!!\n", get_id());
        return L2C_CodeBlockType_Invalid;
    }
    
    return cluster->blocks[*(block_stack.end() - 1)].type;
}

L2C_CodeBlockType EmuInstance::get_last_block_type()
{
    if (!slow) return L2C_CodeBlockType_Invalid;

    if (block_stack.size() <= 1) 
    {
        printf_error("Instance Id %u: Bad last block access!!\n", get_id());
        return L2C_CodeBlockType_Invalid;
    }

    return cluster->blocks[*(block_stack.end() - 2)].type;
}

void EmuInstance::push_block(L2C_CodeBlockType type, int backlog)
{
    if (!slow) return;

    uint64_t addr = backlog ? reg_history[backlog-1].pc : get_pc();
    block_stack.push_back(addr);

    L2C_CodeBlock new_block(addr, type, get_fork_hierarchy());
    printf_verbose("Instance Id %u: Push block %" PRIx64 ", type %s\n", get_id(), addr, new_block.typestr().c_str());
    
    for (auto& block_pair : cluster->blocks)
    {
        auto& block = block_pair.second;
        
        if (!block.addr) continue;

        //printf_verbose("%llx %llx-%llx\n", block_pair.first, block.addr, block.addr_end);
        
        if (addr == block.addr)
        {
            if (cluster->convergable_block(block.addr, get_fork_hierarchy()))
            {
                printf_verbose("Instance Id %u: Block's creator is greater, converging...?\n", get_id());
                return;
            }

            printf_warn("Instance Id %u: Created block %" PRIx64 " resets existing block (prev %s, new %s)...\n", get_id(), addr, block.fork_hierarchy_str().c_str(), new_block.fork_hierarchy_str().c_str());
            break;
        }

        if (addr > block.addr && addr < block.addr_end)
        {
            printf_verbose("Instance Id %u: Created block has address conflicts!\n", get_id());
            printf_verbose("Instance Id %u: Existing, start=%" PRIx64 ", end=%" PRIx64 " Creating start=%" PRIx64 "\n", get_id(), block.addr, block.addr_end, addr);
            cluster->split_block(block.addr, addr);
            return;
        }
    }

    cluster->blocks[addr] = new_block;
}

void EmuInstance::pop_block(bool single)
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

void EmuInstance::print_blockchain()
{
    printf("Instance Id %u block chain:\n", get_id());
    
    int incr = 0;
    for (auto& b : block_stack)
    {
        printf("%u: addr %" PRIx64 ", type %s\n", incr++, cluster->blocks[b].addr, cluster->blocks[b].typestr().c_str());
    }
}

bool EmuInstance::is_basic_emu()
{
    return !slow;
}

uint64_t EmuInstance::get_start_addr()
{
    return start_addr;
}

void EmuInstance::set_start_addr(uint64_t addr)
{
    start_addr = addr;
}

uint64_t EmuInstance::get_end_addr()
{
    return end_addr;
}

void EmuInstance::set_end_addr(uint64_t addr)
{
    end_addr = addr;
}

uint64_t EmuInstance::num_outputted_tokens()
{
    return outputted_tokens;
}

void EmuInstance::inc_outputted_tokens()
{
    outputted_tokens++;
}

void EmuInstance::purge_forks_in_range(uint64_t start, uint64_t end)
{
    for (size_t i = 0; i < forks.size(); i++)
    {   
        auto fork = forks[i];
        // We only want to kill forks which are pending if statements
        // in a subroutine which has been left and re-entered by its
        // parent.
        if (!fork || !fork->get_start_addr()) continue;

        if (fork->get_pc() >= start && fork->get_pc() < end 
            || (start == end && fork->get_pc() == start))
        {
            printf_debug("Instance Id %u: Purging Instance Id %u for being in range %" PRIx64 " to %" PRIx64 "\n", get_id(), fork->get_id(), start, end);
            fork->purge_forks_in_range(start, end);
            fork->terminate();

            delete fork;
            forks[i] = nullptr;
        }
    }
}

void EmuInstance::regs_flush()
{
    uc_write_reg_state(cluster->get_uc(), &regs_cur);
}
    
void EmuInstance::regs_invalidate()
{
    uc_read_reg_state(cluster->get_uc(), &regs_cur);
}
