#include "uc_impl.h"

#include "uc_inst.h"
#include "constants.h"
#include "clustermanager.h"

std::map<uint64_t, uint64_t> hash_cheat;
std::map<uint64_t, uint64_t> hash_cheat_rev;
uint64_t hash_cheat_ptr;
uint32_t sp_part1, sp_part2;

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
    uc_reg_read(uc, UC_ARM64_REG_NZCV, &regs->nzcv);
    
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
    uc_reg_write(uc, UC_ARM64_REG_NZCV, &regs->nzcv);
    
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
    uint64_t x25, x26, x27, x28, fp, lr, sp, pc, nzcv;
    
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
    uc_reg_read(uc, UC_ARM64_REG_NZCV, &nzcv);

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
    printf("nzcv %16.16" PRIx64 " ", nzcv);
    printf("\n");
    printf_debug("fp  %16.16" PRIx64 " ", fp);
    printf("lr  %16.16" PRIx64 " ", lr);
    printf("sp  %16.16" PRIx64 " ", sp);
    printf("pc  %16.16" PRIx64 " ", pc);
    
    
    printf("\n");
}

void hook_code(uc_engine *uc, uint64_t address, uint32_t size, ClusterManager* cluster)
{
    EmuInstance* inst = cluster->get_running_inst();
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

void hook_import(uc_engine *uc, uint64_t address, uint32_t size, ClusterManager* cluster)
{
    uint64_t origin, origin_block;
    std::string name = unresolved_syms_rev[address];
    EmuInstance* inst = cluster->get_running_inst();
    inst->regs_invalidate();
    
    origin = inst->get_jump_history();
    origin_block = cluster->find_containing_block(origin);
    if (!origin_block)
        origin_block = inst->get_last_block();
    printf_verbose("Instance Id %u: Import '%s' from %" PRIx64 ", size %x, block %" PRIx64 "\n", inst->get_id(), name.c_str(), origin, size, origin_block);
    cluster->invalidate_blocktree(inst, inst->get_current_block());
    
    // Add token
    L2C_Token token;
    token.pc = origin;
    token.fork_hierarchy = inst->get_fork_hierarchy();
    token.str = name;
    token.type = L2C_TokenType_Func;

    if (!inst->is_basic_emu() && cluster->converge_points[origin] && inst->has_parent() && inst->get_start_addr())
    {
        // Don't terminate if the token at the convergence point has a larger fork hierarchy
        // Too large a fork hierarchy just means one of the forks got ahead of the root
        // instance and the tokens will be replaced by correct values.
        bool should_term = false;
        uint64_t term_block = 0;
        for (auto& pair : cluster->tokens)
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
            if (origin_block != term_block)
            {
                printf_warn("Instance Id %u: Convergence block is not the same as current block (%" PRIx64 ", %" PRIx64 ")...\n", inst->get_id(), origin_block, term_block);
            }
            
            token.str = "CONV";
            token.type = L2C_TokenType_Meta;
            
            token.args.push_back(origin);
            token.args.push_back(term_block);
            //token.args.push_back(next_closest_block(origin_block, origin));
            
            // Sometimes we get branches which just do nothing, pretend they don't exist
            if (inst->num_outputted_tokens())
                cluster->add_token_by_prio(origin_block, token);
            inst->terminate();
            return;
        }
    }

    bool add_token = false;
    if (!inst->is_basic_emu() && cluster->converge_points[origin])
    {
        for (auto& pair : cluster->tokens)
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

    inst->set_pc(inst->get_lr());
    inst->regs_flush();
    
    uint64_t args[9];
    float fargs[9];
    inst->regs_invalidate();
    args[0] = inst->regs_cur.x0;
    args[1] = inst->regs_cur.x1;
    args[2] = inst->regs_cur.x2;
    args[3] = inst->regs_cur.x3;
    args[4] = inst->regs_cur.x4;
    args[5] = inst->regs_cur.x5;
    args[6] = inst->regs_cur.x6;
    args[7] = inst->regs_cur.x7;
    args[8] = inst->regs_cur.x8;
    
    fargs[0] = inst->regs_cur.s0;
    fargs[1] = inst->regs_cur.s1;
    fargs[2] = inst->regs_cur.s2;
    fargs[3] = inst->regs_cur.s3;
    fargs[4] = inst->regs_cur.s4;
    fargs[5] = inst->regs_cur.s5;
    fargs[6] = inst->regs_cur.s6;
    fargs[7] = inst->regs_cur.s7;
    fargs[8] = inst->regs_cur.s8;

    cluster->converge_points[origin] = true;
    
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
        printf_info("Instance Id %u: lib::L2CAgent::sv_set_function_hash(0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64 ") %s\n", inst->get_id(), args[0], args[1], args[2], unhash[args[2]].c_str());
        
        function_hashes[std::pair<uint64_t, uint64_t>(args[0], args[2])] = args[1];
    }
    else if (name == "lua2cpp::L2CAgentBase::sv_set_status_func(lib::L2CValue const&, lib::L2CValue const&, void*)")
    {
        char tmp[256];
        L2CValue* a = (L2CValue*)inst->uc_ptr_to_real_ptr(args[1]);
        L2CValue* b = (L2CValue*)inst->uc_ptr_to_real_ptr(args[2]);
        uint64_t funcptr = args[3];
        
        uint64_t statusconcat = a->raw << 32 | b->raw;
        std::string kind;
        std::string func;
        if ((a->raw + 1) >= 0x1A6)
            kind = std::to_string(a->raw);
        else
            kind = fighter_status_kind[a->raw + 1];
        if (b->raw >= 23)
            func = std::to_string(b->raw);
        else
            func = status_func[b->raw];

        std::string func_str = kind + "__" + func;
        status_funcs[statusconcat] = func_str;
        
        printf("Instance Id %u: lua2cpp::L2CAgentBase::sv_set_status_func(0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64 ") -> %s,%10" PRIx64 "\n", inst->get_id(), args[0], a->raw, b->raw, funcptr, func_str.c_str(), statusconcat);
        
        function_hashes[std::pair<uint64_t, uint64_t>(args[0], statusconcat)] = funcptr;
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
        //token.args.push_back(args[0]);
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
    else if (name == "lib::L2CValue::L2CValue(lib::L2CValue const&)")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);
        L2CValue* var2 = (L2CValue*)inst->uc_ptr_to_real_ptr(args[1]);

        if (var && var2)
        {
            *var = L2CValue(var2);

            token.args.push_back(args[1]);
            token.args.push_back(var2->type);
        
            if (var2->type == L2C_number)
                token.fargs.push_back(var2->as_number());
            else
                token.args.push_back(var2->raw);
        }
        else
            printf_error("Instance Id %u: Bad L2CValue init, %" PRIx64 ", %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], args[1], origin);
        

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
        
        token.args.push_back(args[1]);
    }
    else if (name == "lib::L2CValue::operator[](int) const")
    {
        //TODO impl
        //token.args.push_back(args[0]);
        token.args.push_back(args[1]);
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
                cluster->add_subreplace_token(inst, origin_block, token);
            add_token = false;

            inst->regs_cur.x0 = 1;
            inst->regs_flush();
            inst->fork_inst();

            inst->regs_cur.x0 = 0;
            args[0] = 0;
        }
    }

    inst->regs_cur.x0 = args[0];
    inst->regs_cur.x1 = args[1];
    inst->regs_cur.x2 = args[2];
    inst->regs_cur.x3 = args[3];
    inst->regs_cur.x4 = args[4];
    inst->regs_cur.x5 = args[5];
    inst->regs_cur.x6 = args[6];
    inst->regs_cur.x7 = args[7];
    inst->regs_cur.x8 = args[8];
    
    inst->regs_cur.s0 = fargs[0];
    inst->regs_cur.s1 = fargs[1];
    inst->regs_cur.s2 = fargs[2];
    inst->regs_cur.s3 = fargs[3];
    inst->regs_cur.s4 = fargs[4];
    inst->regs_cur.s5 = fargs[5];
    inst->regs_cur.s6 = fargs[6];
    inst->regs_cur.s7 = fargs[7];
    inst->regs_cur.s8 = fargs[8];
    inst->regs_flush();
    
    if (add_token)
        cluster->add_subreplace_token(inst, origin_block, token);

    inst->pop_block();
}

void hook_memrw(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, ClusterManager* cluster)
{
    EmuInstance* inst = cluster->get_running_inst();
    uint32_t cur_crc, finding;
    uint8_t crcidx, crcbyte;
    switch(type) 
    {
        default: break;
        case UC_MEM_READ:
            value = *(uint64_t*)(inst->uc_ptr_to_real_ptr(addr));
            printf_verbose("Instance Id %u: Memory is being READ at 0x%" PRIx64 ", data size = %u, data value = 0x%" PRIx64 "\n", inst->get_id(), addr, size, value);
            
            if (size == 4 && addr >= STACK && addr <= STACK_END)
            {
                uint32_t hash_maybe = *(uint32_t*)inst->uc_ptr_to_real_ptr(addr);
                
                if (hash_maybe < 0x100)
                    sp_part1 = hash_maybe;
                else
                    sp_part2 = hash_maybe << 8;

                if (unhash_parts[hash_maybe] != "")
                {
                    last_crcs.insert(hash_maybe);
                    //printf("sp hash %08x %s\n", hash_maybe, unhash_parts[hash_maybe].c_str());
                }
                
                hash_maybe = sp_part1 | sp_part2;
                if (unhash_parts[hash_maybe] != "")
                {
                    last_crcs.insert(hash_maybe);
                    //printf("sp hash %08x %s\n", hash_maybe, unhash_parts[hash_maybe].c_str());
                }
            }
                 
            if (addr >= unresolved_syms["phx::detail::CRC32Table::table_"] && addr < unresolved_syms["phx::detail::CRC32Table::table_"] + sizeof(crc32_tab))
            {
                crcidx = (addr - unresolved_syms["phx::detail::CRC32Table::table_"]) / 4;
                //uc_print_regs(uc);
                
                //printf("idx %x accessed\n", crcidx);
                
                std::set<uint32_t> potential_32_8s;
                std::set<uint8_t> potential_8_0s;
                std::set<uint32_t> potential_hash;
                for (int i = UC_ARM64_REG_X0; i <= UC_ARM64_REG_X28; i++)
                {
                    uint64_t reg;
                    uc_reg_read(uc, i, &reg);
                    
                    //if (reg >> 32 == 0)
                    {
                        uint8_t reg_inv = reg ^ 0xFF;
                        if (unhash_parts[(uint32_t)reg] != "")
                        {
                            potential_hash.insert((uint32_t)reg);
                            //printf("CRC32? %08x %s\n", (uint32_t)reg, unhash_parts[reg].c_str());
                        }
                        else if (unhash[reg] != "")
                        {
                            uint32_t inv = (uint32_t)(reg ^ ~0);
                            potential_hash.insert(inv);
                            //printf("CRC32? %08x %s\n", inv, unhash_parts[inv].c_str());
                        }
                        
                        if (reg <= 0xFFFFFF)
                            potential_32_8s.insert(reg);
                        if (reg <= 0xFF)
                            potential_8_0s.insert(reg);
                    }
                }
                
                for (uint32_t pot_32_8 : potential_32_8s)
                {
                    for (uint8_t pot_8_0 : potential_8_0s)
                    {
                        uint32_t hash = pot_32_8 << 8 | pot_8_0;
                        if (unhash_parts[hash] != "")
                        {
                            potential_hash.insert(hash);
                            //printf("CRC32? %08x %s\n", hash, unhash_parts[hash].c_str());
                        }
                    }
                }
                
                potential_hash.insert(0xFFFFFFFF);
                
                for (uint32_t hash : last_crcs)
                    potential_hash.insert(hash);
                
                last_crcs.clear();
                for (uint32_t pot_last_crc : potential_hash)
                {
                    uint32_t cur_crc = crc32_tab[crcidx] ^ (pot_last_crc >> 8);
                    finding = cur_crc ^ (pot_last_crc >> 8);
                    for (int i = 0; i < 0x100; i++)
                    {
                        if (crc32_tab[i] == finding)
                        {
                            crcbyte = i ^ (uint8_t)pot_last_crc;
                            if ((crcbyte >= 'a' && crcbyte <= 'z') || (crcbyte >= '0' && crcbyte <= '9') || crcbyte == '_')
                            {
                                if (unhash_parts[pot_last_crc] != "" || pot_last_crc == 0xFFFFFFFF)
                                {
                                    std::string cur_str = unhash_parts[pot_last_crc] + (char)crcbyte;
                                    unhash_parts[cur_crc] = cur_str;
                                    unhash[(uint32_t)(cur_crc ^ ~0) | cur_str.length() << 32] = cur_str;
                                }

                                //printf("last %x cur %x hashed %c %s\n", pot_last_crc, cur_crc, crcbyte, unhash_parts[cur_crc].c_str());
                                
                                last_crcs.insert(cur_crc);
                            }
                        }
                    }
                }
                
                //printf("CRC32 %08x %c (%x)\n", last_crc, crcidx, crcidx);
            }
            break;
        case UC_MEM_WRITE:
            if (addr >= IMPORTS && addr < IMPORTS_END)
                printf("aaaaaaaaaaaaaa\n");
            printf_verbose("Instance Id %u: Memory is being WRITE at 0x%" PRIx64 ", data size = %u, data value = 0x%" PRIx64 "\n", inst->get_id(), addr, size, value);
            break;
    }
    return;
}

// callback for tracing memory access (READ or WRITE)
bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, ClusterManager* cluster)
{
    EmuInstance* inst = cluster->get_running_inst();
    inst->regs_invalidate();
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
