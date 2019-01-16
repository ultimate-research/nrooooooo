#ifndef CLUSTERMANAGER_H
#define CLUSTERMANAGER_H

#include <map>
#include <string>
#include <stdint.h>
#include <thread>
#include "uc_inst.h"

// memory addresses for different segments
#define NRO 0x100000000
#define NRO_SIZE (0x880000)

#define IMPORTS 0xEEEE000000000000
#define IMPORTS_SIZE (0x100000)
#define IMPORTS_END (IMPORTS + IMPORTS_SIZE)

#define HEAP 0xBBBB000000000000
#define HEAP_SIZE (0x60000)

#define STACK 0xFFFF000000000000
#define STACK_SIZE (0x18000) // Check this...
#define STACK_END (STACK + STACK_SIZE)

extern int cluster_id_cnt;

class ClusterManager
{
private:
    int id;
    void* nro_mem;
    void* import_mem;
    uc_engine* uc;
    EmuInstance* inst;
    EmuInstance* running;
    int instance_id_cnt = 0;
    std::map<uint64_t, bool> fork_origins;
    std::map<uint64_t, bool> block_printed;
    
    bool heap_fixed = false;

public:
    std::map<uint64_t, std::set<L2C_Token> > tokens;
    std::map<uint64_t, bool> converge_points;
    std::map<uint64_t, L2C_CodeBlock> blocks;

    ClusterManager(std::string nro_path)
    {
        nro_mem = malloc(NRO_SIZE);
        import_mem = malloc(IMPORTS_SIZE);
        FILE* f_nro = fopen(nro_path.c_str(), "rb");
        fread(nro_mem, NRO_SIZE, 1, f_nro);
        fclose(f_nro);
        
        nro_assignsyms(nro_mem);
        nro_relocate(nro_mem);

        uc_init();
        inst = new EmuInstance(this);
        
        // Write in constants
        memcpy(uc_ptr_to_real_ptr(unresolved_syms["phx::detail::CRC32Table::table_"]), crc32_tab, sizeof(crc32_tab));
        
        id = cluster_id_cnt++;
    }
    
    ~ClusterManager() 
    {
        delete inst;
        
        uc_mem_unmap(uc, IMPORTS, IMPORTS_SIZE);
        uc_mem_unmap(uc, NRO, NRO_SIZE);
        
        uc_close(uc);
        
        free(import_mem);
        free(nro_mem);
    }
    
    ClusterManager(ClusterManager* to_clone)
    {
        instance_id_cnt = 0;
        nro_mem = malloc(NRO_SIZE);
        import_mem = malloc(IMPORTS_SIZE);
        memcpy(nro_mem, to_clone->nro_mem, NRO_SIZE);
        memcpy(import_mem, to_clone->import_mem, IMPORTS_SIZE);
        
        fork_origins = to_clone->fork_origins;
        block_printed = to_clone->block_printed;
        tokens = to_clone->tokens;
        converge_points = to_clone->converge_points;
        blocks = to_clone->blocks;
        
        uc_init();
        
        inst = new EmuInstance(this, to_clone->inst);
        
        // Write in constants
        memcpy(uc_ptr_to_real_ptr(unresolved_syms["phx::detail::CRC32Table::table_"]), crc32_tab, sizeof(crc32_tab));
        
        id = cluster_id_cnt++;
    }
    
    void set_running_inst(EmuInstance* inst)
    {
        running = inst;
    }
    
    EmuInstance* get_running_inst()
    {
        return running;
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
            printf_error("Cluster %u: Failed on uc_open() with error returned: %u (%s)\n",
                    get_id(), err, uc_strerror(err));
            return err;
        }
        
        uint32_t x;
        uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &x);
        x |= 0x300000; // set FPEN bit
        uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &x);

        // import hooks
        for (auto pair : unresolved_syms)
        {
            uc_hook trace;

            uc_hook_add(uc, &trace, UC_HOOK_CODE, (void*)hook_import, this, pair.second, pair.second);
        }
        
        // granular hooks
        //uc_hook_add(uc, &trace1, UC_HOOK_CODE, (void*)hook_code, this, 1, 0);
        uc_hook_add(uc, &trace2, UC_HOOK_MEM_UNMAPPED, (void*)hook_mem_invalid, this, 1, 0);
        uc_hook_add(uc, &trace3, UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, (void*)hook_memrw, this, 1, 0);
        
        uc_mem_map_ptr(uc, NRO, NRO_SIZE, UC_PROT_ALL, nro_mem);    
        uc_mem_map_ptr(uc, IMPORTS, IMPORTS_SIZE, UC_PROT_ALL, import_mem);
        
        return err;
    }
    
    uc_engine* get_uc()
    {
        return uc;
    }
    
    void set_heap_fixed(bool fixed)
    {
        heap_fixed = fixed;
    }
    
    bool get_heap_fixed()
    {
        return heap_fixed;
    }
    
    int get_id()
    {
        return id;
    }
    
    void* get_nro_mem()
    {
        return nro_mem;
    }
    
    void* get_import_mem()
    {
        return import_mem;
    }

    void* uc_ptr_to_real_ptr(uint64_t ptr)
    {
        return inst->uc_ptr_to_real_ptr(ptr);
    }
    
    uint64_t heap_alloc(uint32_t size)
    {
        return inst->heap_alloc(size);
    }
    
    void set_fork_origin(uint64_t pc)
    {
        fork_origins[pc] = true;
    }
    
    bool is_fork_origin(uint64_t pc)
    {
        return fork_origins[pc];
    }
    
    void clear_state()
    {
        tokens.clear();
        blocks.clear();
        converge_points = std::map<uint64_t, bool>();
    }
    
    int create_id()
    {
        return instance_id_cnt++;
    }
    
    void remove_matching_tokens(uint64_t addr, std::string str);
    void remove_block_matching_tokens(uint64_t block, uint64_t addr, std::string str);
    bool token_by_addr_and_name_exists(uint64_t pc, std::string str);
    void add_token_by_prio(uint64_t block, L2C_Token token);
    void add_subreplace_token(EmuInstance* inst, uint64_t block, L2C_Token token);
    uint64_t find_containing_block(uint64_t addr);
    void clean_and_verify_blocks(uint64_t func, bool is_noreturn);
    std::string print_block(uint64_t b);
    std::string print_blocks(uint64_t func, std::unordered_map<uint64_t, bool>* block_visited = nullptr);
    
    void invalidate_blocktree(EmuInstance* inst, uint64_t func);
    uint64_t execute(uint64_t start, bool run_slow, bool reset_heap_after, uint64_t x0 = 0, uint64_t x1 = 0, uint64_t x2 = 0, uint64_t x3 = 0);
    std::thread* execute_threaded(uint64_t start, void (*on_complete)(ClusterManager* cluster, uint64_t ret, void* data), void* data, bool run_slow, bool reset_heap_after, uint64_t x0 = 0, uint64_t x1 = 0, uint64_t x2 = 0, uint64_t x3 = 0);
    void split_block(uint64_t block, uint64_t addr);
    bool convergable_block(uint64_t block, std::vector<int> comp);
    uint64_t block_hash(uint64_t addr);
};

#endif // CLUSTERMANAGER_H
