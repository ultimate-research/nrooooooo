#include "clustermanager.h"

#include <algorithm>
#include <cstring>
#include <atomic>

int cluster_id_cnt = 0;

void ClusterManager::remove_matching_tokens(uint64_t addr, std::string str)
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

void ClusterManager::remove_block_matching_tokens(uint64_t block, uint64_t addr, std::string str)
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

bool ClusterManager::token_by_addr_and_name_exists(uint64_t pc, std::string str)
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

void ClusterManager::add_token_by_prio(uint64_t block, L2C_Token token)
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
}

void ClusterManager::add_subreplace_token(EmuInstance* inst, uint64_t block, L2C_Token token)
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

    add_token_by_prio(block, token);
    
    if (function_tail)
    {
        token.str = "SUB_RET";
        token.type = L2C_TokenType_Meta;
        token.args.clear();
        token.fargs.clear();
        add_token_by_prio(block, token);
        
        inst->pop_block();
        
        if (token.pc+4 >= blocks[block].addr_end)
            blocks[block].addr_end = token.pc+4;
    }
}

uint64_t ClusterManager::find_containing_block(uint64_t addr)
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


void ClusterManager::clean_and_verify_blocks(uint64_t func, bool is_noreturn)
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
                
                if (!tokens[t.args[0]].size())
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
            //printf("%llx %llx\n", blocks[b].addr, blocks[b].addr_end);
            if (addr_in_block[i])
                printf_warn("Address range overlap at %" PRIx64 " in block %" PRIx64 "\n", i, b);

            addr_in_block[i] = true;
        }
        
        // With is_noreturn, one missing exit token is permitted.
        if (!num_jumps && !is_noreturn)
        {
            printf_warn("Block %" PRIx64 " is missing an exit token!\n", b);
            is_noreturn = false;
        }
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
                    printf_debug("Pruning %s", token.to_string(this).c_str());
                }
                block_tokens.erase(token);
            }
        }
    }
}

std::string ClusterManager::print_block(uint64_t b)
{
    char tmp[256];
    std::string out = "";
    /*if (block_printed[b])
    {
        snprintf(tmp, 255, "\nBlock %" PRIx64 " type %u, size %x, %u tokens, creation %s: See earlier definition\n",  block_hash(b), blocks[b].type, blocks[b].size(), tokens[b].size(), blocks[b].fork_hierarchy_str().c_str());
        out += std::string(tmp);
        return out;
    }*/

    //snprintf(tmp, 255, "\nBlock %" PRIx64 " (end %" PRIx64 ") type %u, size %x, %u tokens, creation %s:\n", b, blocks[b].addr_end, blocks[b].type, blocks[b].size(), tokens[b].size(), blocks[b].fork_hierarchy_str().c_str());
    snprintf(tmp, 255, "\nBlock %" PRIx64 " type %u, size %x, %u tokens, creation %s:\n", block_hash(b), blocks[b].type, blocks[b].size(), tokens[b].size(), blocks[b].fork_hierarchy_str().c_str());
    out += std::string(tmp);

    for (auto& t : tokens[b])
    {
        out += t.to_string(this, b);
    }
    
    block_printed[b] = true;
    
    return out;
}

std::string ClusterManager::print_blocks(uint64_t func, std::unordered_map<uint64_t, bool>* block_visited)
{
    char tmp[256];
    std::string out = "";
    std::map<uint64_t, bool> block_skipped;
    std::vector<uint64_t> block_visited_here;
    std::vector<uint64_t> block_list;
    block_list.push_back(func);

    bool needs_free = false;
    if (!block_visited)
    {
        block_visited = new std::unordered_map<uint64_t, bool>();
        needs_free = true;
    }
    
    if ((*block_visited)[func]) return "";
    
    (*block_visited)[func] = true;
    block_visited_here.push_back(func);

    while(block_list.size())
    {
        uint64_t b = *(block_list.end() - 1);
        block_list.pop_back();

        if (!tokens[b].size()) continue;

        //out += print_block(b);
        for (auto t : tokens[b])
        {
            if (t.str == "SUB_BRANCH" || t.str == "SUB_GOTO" || t.str == "DIV_FALSE" || t.str == "DIV_TRUE" || t.str == "CONV" || t.str == "BLOCK_MERGE" || t.str == "SPLIT_BLOCK_MERGE")
            {
                if (!(*block_visited)[t.args[0]] && !block_skipped[t.args[0]] && t.str != "SUB_BRANCH")
                {
                    block_list.push_back(t.args[0]);
                    (*block_visited)[t.args[0]] = true;
                    block_visited_here.push_back(t.args[0]);
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
        out += print_block(b);
    }
    
    for (auto& pair : block_skipped)
    {
        uint64_t b = pair.first;
        
        out += print_blocks(b, block_visited);
    }
    
    if (needs_free) delete block_visited;
    
    return out;
}

void ClusterManager::invalidate_blocktree(EmuInstance* inst, uint64_t func)
{
    std::map<uint64_t, bool> block_visited = std::map<uint64_t, bool>();
    std::vector<uint64_t> block_list = std::vector<uint64_t>();
    block_list.push_back(func);
    block_visited[func] = true;
    
    //printf(print_blocks(func).c_str());

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
                    
                    //printf("%llx %s\n", t.args[0], t.str.c_str());
                }
            }
        }
        
        std::sort(block_list.begin(), block_list.end(), std::greater<int>());
    }
    
    for (auto& pair : block_visited)
    {
        printf_verbose("Instance Id %u: Invalidated block %" PRIx64 " (type %u) from chain %" PRIx64 "\n", inst->get_id(), pair.first, blocks[pair.first].type, func);
        
        inst->purge_forks_in_range(blocks[pair.first].addr, blocks[pair.first].addr_end);
    
        //printf("%llx %llx\n", blocks[pair.first].addr, blocks[pair.first].addr_end);
        for (uint64_t i = blocks[pair.first].addr; i < blocks[pair.first].addr_end; i++)
        {
            converge_points[i] = false;
            fork_origins[i] = false;
        }
    
        // In case there's anything weird going on...
        for (auto& t : tokens[pair.first])
        {
            converge_points[t.pc] = false;
            fork_origins[t.pc] = false;
        }
    
        tokens[pair.first].clear();
        blocks[pair.first] = L2C_CodeBlock();
    }
    printf_verbose("Instance Id %u: Invalidated %u block(s)\n", inst->get_id(), block_visited.size());
}

uint64_t ClusterManager::execute(uint64_t start, bool run_slow, bool reset_heap_after, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3)
{
    instance_id_cnt = 1;
    return inst->execute(start, run_slow, reset_heap_after, x0, x1, x2, x3);
}

void thread_func(ClusterManager* cluster, uint64_t start, bool run_slow, bool reset_heap_after, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, void (*on_complete)(ClusterManager* cluster, uint64_t ret, void* data), void* data)
{
    uint64_t ret = cluster->execute(start, run_slow, reset_heap_after, x0, x1, x2, x3);
    
    if (on_complete)
    {
        on_complete(cluster, ret, data);
    }
}

std::thread* ClusterManager::execute_threaded(uint64_t start, void (*on_complete)(ClusterManager* cluster, uint64_t ret, void* data), void* data, bool run_slow, bool reset_heap_after, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3)
{
    return new std::thread(thread_func, this, start, run_slow, reset_heap_after, x0, x1, x2, x3, on_complete, data);
}

void ClusterManager::split_block(uint64_t block, uint64_t addr)
{
    uint64_t splitting_addr = blocks[block].addr;
    uint64_t splitting_addr_end = blocks[block].addr_end;

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

    printf_verbose("Cluster Manager: Splitting... %llx-%llx %llx-%llx\n", a.addr, a.addr_end, b.addr, b.addr_end);

    for (auto& token : to_split)
    {
        if (token.pc >= a.addr && token.pc < a.addr_end)
        {
            tokens[splitting_addr].insert(token);
            
            last_a_token = token;
            //printf("a ");
            //token.print();
        }
        else if (token.pc >= b.addr && token.pc < b.addr_end)
        {
            tokens[addr].insert(token);
            
            //printf("b ");
            //token.print();
        }
        else if (!((token.str == "BLOCK_MERGE" || token.str == "SPLIT_BLOCK_MERGE") && token.pc == b.addr_end))
        {
            printf_error("Cluster Manager: Failed to assign token at %" PRIx64 " during split!\n%s", token.pc, token.to_string(this));
        }
    }

    L2C_Token token;
    token.pc = a.addr_end;
    token.fork_hierarchy = last_a_token.fork_hierarchy;
    token.str = "SPLIT_BLOCK_MERGE";
    token.type = L2C_TokenType_Meta;
    token.args.push_back(b.addr);
    add_token_by_prio(a.addr, token);

    blocks[splitting_addr] = a;
    blocks[addr] = b;
}

bool ClusterManager::convergable_block(uint64_t block, std::vector<int> comp)
{
    auto b = blocks[block];
    if (!b.fork_hierarchy.size()) return false;
    if (b.fork_hierarchy.size() == 1 && comp.size() > 1) return true;
    if (b.fork_hierarchy == comp && comp.size() == 1 && tokens[block].size()) return true;

    if (b.fork_hierarchy.size() == comp.size())
        return b.creator() < comp[0];

    return b.fork_hierarchy.size() < comp.size();
}

uint64_t ClusterManager::block_hash(uint64_t addr)
{
    uint32_t crc = 0;
    for (auto& token : tokens[addr])
    {
        for (int val : token.fork_hierarchy)
            crc = crc32_part(&val, 4, crc);

        crc = crc32_part(token.str.c_str(), token.str.length(), crc);
        crc = crc32_part(&token.type, sizeof(token.type), crc);
        if (token.str == "SUB_BRANCH" || token.str == "SUB_GOTO" || token.str == "DIV_FALSE" || token.str == "DIV_TRUE" || token.str == "CONV" || token.str == "BLOCK_MERGE" || token.str == "SPLIT_BLOCK_MERGE")
        {

        }
        else
        {
            for (uint64_t arg : token.args)
                crc = crc32_part(&arg, sizeof(arg), crc);
            
            for (float farg : token.fargs)
                crc = crc32_part(&farg, sizeof(farg), crc);
        }
    }
    
    return crc | (uint64_t)(tokens[addr].size() << 32);
}
