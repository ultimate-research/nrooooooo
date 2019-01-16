#ifndef EMUINSTANCE_H
#define EMUINSTANCE_H

#include "main.h"

#include <atomic>
#include <cstring>
#include <vector>
#include <deque>
#include <map>
#include <unordered_set>
#include "uc_impl.h"
#include "logging.h"

class ClusterManager;

#define MAGIC_IMPORT 0xF00F1B015
#define INSTR_RET 0xD65F03C0

#define REG_HISTORY_LIMIT 10
#define JUMP_HISTORY_LIMIT 10

// 1GiB mem
#define MAX_UC_MEM 0x40000000

extern std::atomic<int> uc_insts_active;
extern std::atomic<uint64_t> uc_memory_use;

class EmuInstance
{
private:
    ClusterManager* cluster;
    uc_err err_last;
    void* nro;
    void* imports;
    void* heap;
    uint64_t heap_size = 0;
    void* stack;
    
    std::vector<EmuInstance*> forks;
    EmuInstance* parent;
    uint64_t start_addr = 0;
    uint64_t end_addr = 0;
    uint64_t outputted_tokens = 0;
    
    bool slow;
    bool uc_term;
    int instance_id;
    
    std::vector<uint64_t> block_stack;
    std::deque<uc_reg_state> reg_history;
    std::deque<uint64_t> jump_history;

public:
    uc_reg_state regs_cur;
    std::vector<L2CValue> lua_stack;
    std::map<uint64_t, L2CValue*> lua_active_vars;

    EmuInstance(ClusterManager* parent_cluster);
    EmuInstance(ClusterManager* parent_cluster, EmuInstance* to_clone, EmuInstance* parent = nullptr);
    ~EmuInstance();
    
    ClusterManager* get_cluster()
    {
        return cluster;
    }
    
    int cluster_id();
    void forks_complete();
    void fork_inst();
    void add_import_hook(uint64_t addr);
    uc_err uc_run_slice();
    uint64_t execute(uint64_t start, bool run_slow, bool reset_heap_after, uint64_t x0 = 0, uint64_t x1 = 0, uint64_t x2 = 0, uint64_t x3 = 0);
    void* uc_ptr_to_real_ptr(uint64_t ptr);
    uint64_t heap_alloc(uint32_t size);
    bool is_term();
    void terminate();
    int get_id();
    int parent_id();
    void set_pc(uint64_t pc);
    void set_sp(uint64_t sp);
    void set_lr(uint64_t lr);
    uint64_t get_pc();
    uint64_t get_sp();
    uint64_t get_lr();
    bool has_parent();
    std::vector<int> get_fork_hierarchy();
    uint64_t get_jump_history(size_t depth = 0);
    void push_jump(uint64_t addr);
    uint64_t get_current_block();
    uint64_t get_last_block();
    L2C_CodeBlockType get_current_block_type();
    L2C_CodeBlockType get_last_block_type();
    void push_block(L2C_CodeBlockType type = L2C_CodeBlockType_Subroutine, int backlog = 0);
    void pop_block(bool single = false);
    void print_blockchain();
    bool is_basic_emu();
    uint64_t get_start_addr();
    void set_start_addr(uint64_t addr);
    uint64_t get_end_addr();
    void set_end_addr(uint64_t addr);
    uint64_t num_outputted_tokens();
    void inc_outputted_tokens();
    void purge_forks_in_range(uint64_t start, uint64_t end);
    
    void regs_flush();
    void regs_invalidate();
};

#endif // EMUINSTANCE_H
