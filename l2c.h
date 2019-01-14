#ifndef L2C_H
#define L2C_H

#include <vector>
#include <map>
#include <set>

#include "useful.h"
#include "crc32.h"

struct L2CValue;
struct L2C_Token;
extern std::map<uint64_t, std::set<L2C_Token> > tokens;

struct Hash40
{
    uint64_t hash : 40;
};

enum L2C_TokenType
{
    L2C_TokenType_Invalid = 0,
    L2C_TokenType_Func = 1,
    L2C_TokenType_Branch = 2,
    L2C_TokenType_Meta = 3,
};

struct L2C_Token
{
    uint64_t pc;
    std::vector<int> fork_hierarchy;
    std::string str;
    L2C_TokenType type;
    std::vector<uint64_t> args;
    std::vector<float> fargs;
    
    L2C_Token() : pc(0), fork_hierarchy(), str(""), type(L2C_TokenType_Invalid), args(), fargs() {}
    
    bool operator<(const L2C_Token& comp) const
    {
        if (pc == comp.pc) 
        {
            if (fork_hierarchy == comp.fork_hierarchy)
            {
                if (type == comp.type)
                {
                    if (str == comp.str)
                    {
                        if (args == comp.args)
                        {
                            return fargs < comp.fargs;
                        }
                        
                        return args < comp.args;
                    }
                    return str < comp.str;
                }
                
                return type < comp.type;
            }
            
            return fork_hierarchy < comp.fork_hierarchy;
        }
 
        return pc < comp.pc;
    }
    
    std::string fork_hierarchy_str() const
    {
        std::string out = "";
        
        for (size_t i = fork_hierarchy.size(); i > 0; i--)
        {
            out += std::to_string(fork_hierarchy[i-1]);
            if (i > 1)
                out += "->";
        }
        
        return out;
    }
    
    std::string to_string(uint64_t rel = 0) const;
};

enum L2C_CodeBlockType
{
    L2C_CodeBlockType_Invalid = 0,
    L2C_CodeBlockType_Subroutine,
    L2C_CodeBlockType_Goto,
    L2C_CodeBlockType_Fork,
};

struct L2C_CodeBlock
{
    uint64_t addr;
    uint64_t addr_end;
    L2C_CodeBlockType type;
    std::vector<int> fork_hierarchy;
    
    uint64_t hash_stash;
    
    L2C_CodeBlock() : addr(0), addr_end(0), type(L2C_CodeBlockType_Invalid), hash_stash(0) {}
    L2C_CodeBlock(uint64_t addr, L2C_CodeBlockType type, std::vector<int> fork_hierarchy) : addr(addr), addr_end(addr), type(type), fork_hierarchy(fork_hierarchy), hash_stash(0) {}
    
    uint64_t size()
    {
        return addr_end - addr;
    }
    
    uint64_t num_tokens()
    {
        return tokens[addr].size();
    }
    
    std::string typestr()
    {
        std::string typestr = "<unk>";
        if (type == L2C_CodeBlockType_Invalid)
        {
            typestr = "Invalid";
        }
        else if (type == L2C_CodeBlockType_Subroutine)
        {
            typestr = "Subroutine";
        }
        else if (type == L2C_CodeBlockType_Goto)
        {
            typestr = "Goto";
        }
        else if (type == L2C_CodeBlockType_Fork)
        {
            typestr = "Fork";
        }
        return typestr;
    }
    
    int creator()
    {
        if (!fork_hierarchy.size()) return -1;

        return fork_hierarchy[0];
    }
    
    std::string fork_hierarchy_str() const
    {
        std::string out = "";
        
        for (size_t i = fork_hierarchy.size(); i > 0; i--)
        {
            out += std::to_string(fork_hierarchy[i-1]);
            if (i > 1)
                out += "->";
        }
        
        return out;
    }
    
    bool convergable_block(std::vector<int> comp)
    {
        if (!fork_hierarchy.size()) return false;
        if (fork_hierarchy.size() == 1 && comp.size() > 1) return true;
        if (fork_hierarchy == comp && comp.size() == 1 && num_tokens()) return true;

        if (fork_hierarchy.size() == comp.size())
            return creator() < comp[0];

        return fork_hierarchy.size() < comp.size();
    }
    
    uint64_t hash()
    {
        if ((hash_stash >> 32) == num_tokens()) return hash_stash;
        
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
        
        hash_stash = crc | (uint64_t)(num_tokens() << 32);
        return hash_stash;
    }
};

enum L2CVarType
{
    L2C_void = 0,
    L2C_bool = 1,
    L2C_integer = 2,
    L2C_number = 3,
    L2C_pointer = 4,
    L2C_table = 5,
    L2C_inner_function = 6,
    L2C_hash = 7,
    L2C_string = 8,
};

struct L2CTable_meta
{
    uint64_t a;
    uint64_t b;
    uint64_t c;
    uint64_t d;
};

struct L2CTable
{
    uint32_t refcnt;
    uint32_t unk;
    
    uint64_t begin; // L2CValue*
    uint64_t end; // L2CValue*
    uint64_t also_end; // L2CValue*
    L2CTable_meta meta;
    uint64_t unk_ptr;
};

struct L2CInnerFunctionBase
{
    uint64_t unk;
    uint32_t refcnt;
};

struct L2CValue
{
    uint32_t type;
    uint32_t unk;
    union
    {
        uint64_t raw;
        float raw_float;
        void* raw_pointer;
        L2CTable* raw_table;
        L2CInnerFunctionBase* raw_innerfunc;
        std::string* raw_string;
    };
    
    L2CValue(void)
    {
        type = L2C_void;
    }
    
    L2CValue(bool val)
    {
        type = L2C_bool;
        raw = val ? 1 : 0;
    }
    
    L2CValue(int val)
    {
        type = L2C_integer;
        raw = val;
    }
    
    L2CValue(uint64_t val)
    {
        type = L2C_integer;
        raw = val;
    }
    
    L2CValue(long val)
    {
        type = L2C_integer;
        raw = val;
    }
    
    L2CValue(Hash40 val)
    {
        type = L2C_hash;
        raw = val.hash;
    }
    
    L2CValue(void* val)
    {
        type = L2C_pointer;
        raw_pointer = val;
    }
    
    L2CValue(float val)
    {
        type = L2C_number;
        raw_float = val;
    }
    
    L2CValue(char const* val)
    {
        type = L2C_string;
        raw_string = new std::string(val);
    }
    
    L2CValue(L2CValue* val)
    {
        type = val->type;
        raw = val->raw;
    }
    
    bool as_bool(void)
    {
        return raw & 1;
    }
    
    int64_t as_integer(void)
    {
        return (int64_t)raw;
    }
    
    float as_number(void)
    {
        if (type == L2C_integer)
        {
            return (float)as_integer();
        }

        return raw_float;
    }
    
    void* as_pointer(void)
    {
        if (type == L2C_pointer)
            return raw_pointer;

        return nullptr;
    }
    
    L2CTable* as_table(void)
    {
        if (type == L2C_table)
            return raw_table;

        return nullptr;
    }
    
    L2CInnerFunctionBase* as_inner_function(void)
    {
        if (type == L2C_inner_function)
            return raw_innerfunc;

        return nullptr;
    }
    
    uint64_t as_hash(void)
    {
        if (type == L2C_hash || type == L2C_integer)
            return raw & 0xFFFFFFFFFF;

        return 0;
    }
    
    const char* as_string(void)
    {
        if (type == L2C_string)
        {
            return raw_string->c_str();
        }

        return "";
    }
    
    uint64_t length(void)
    {
        if (type == L2C_string)
        {
            return raw_string->length();
        }
        else if (type == L2C_table)
        {
            return 0; //TODO
        }
        
        return 0;
    }
};

struct L2CAgent
{
    uint64_t vtable;
    uint64_t lua_state_agent;
    uint64_t unk10;
    uint64_t unk18;
    uint64_t unk20;
    uint64_t unk28;
    uint64_t unk30;
    uint64_t unk38;
    uint64_t lua_state_agentbase;
};

struct lua_State
{
    uint64_t unk0;
    uint64_t unk8;
    uint64_t unk10;
    uint64_t unk18;
    uint64_t unk20;
    uint64_t unk28;
    uint64_t unk30;
    uint64_t unk38;
    uint64_t unk40;
    uint64_t unkptr48;
    uint64_t unkptr50;
    uint64_t unk58;
    uint64_t unk60;
    uint64_t unk68;
    uint64_t unk70;
    uint64_t unk78;
    uint64_t unk80;
    uint64_t unk88;
    uint64_t unk90;
    uint64_t unkptr98;
    uint64_t unkptrA0;
    uint64_t unkA8;
    uint64_t unkB0;
    uint64_t unkB8;
    uint64_t unkC0;
    uint64_t unkptrC8;
    uint64_t unkD0;
    uint64_t unkD8;
    uint64_t unkE0;
    uint64_t unkE8;
    uint64_t unkF0;
    uint64_t unkF8;
    uint64_t unk100;
    uint64_t unk108;
    uint64_t unk110;
    uint64_t unkptr118;
    uint64_t unk120;
    uint64_t unk128;
    uint64_t unk130;
    uint64_t unk138;
    uint64_t unk140;
    uint64_t unk148;
    uint64_t unk150;
    uint64_t unkptr158;
    uint64_t unk160;
    uint64_t unk168;
    uint64_t unk170;
    uint64_t unk178;
    uint64_t unk180;
    uint64_t unk188;
    uint64_t unk190;
    uint64_t unk198;
    uint64_t unk1A0;
    uint64_t unk1A8;
    uint64_t unk1B0;
    uint64_t unk1B8;
    uint64_t unk1C0;
    uint64_t unk1C8;
    uint64_t unk1D0;
    uint64_t unk1D8;
    uint64_t unk1E0;
    uint64_t unk1E8;
    uint64_t unk1F0;
    uint64_t unk1F8;
    uint64_t unk200;
    uint64_t unk208;
    uint64_t unk210;
    uint64_t unk218;
};

struct lua_Stateptr48
{
    uint64_t vtable;
};

struct lua_Stateptr50
{
    uint64_t vtable;
};

struct lua_Stateptr98
{
    uint64_t vtable;
};

struct lua_StateptrA0
{
    uint64_t vtable;
};

struct lua_StateptrC8
{
    uint64_t vtable;
};

struct lua_Stateptr118
{
    uint64_t vtable;
};

struct lua_Stateptr158
{
    uint64_t vtable;
};

struct lua_Stateptr50Vtable
{
    uint64_t unk0;
    uint64_t unk8;
    uint64_t unk10;
    uint64_t unk18;
    uint64_t unk20;
    uint64_t unk28;
    uint64_t unk30;
    uint64_t unk38;
    uint64_t unk40;
    uint64_t unk48;
    uint64_t unk50;
    uint64_t unk58;
    uint64_t unk60;
    uint64_t unk68;
    uint64_t unk70;
    uint64_t unk78;
    uint64_t unk80;
    uint64_t unk88;
    uint64_t unk90;
    uint64_t unk98;
    uint64_t unkA0;
    uint64_t unkA8;
    uint64_t unkB0;
    uint64_t unkB8;
    uint64_t unkC0;
    uint64_t unkC8;
    uint64_t unkD0;
    uint64_t unkD8;
    uint64_t unkE0;
    uint64_t unkE8;
    uint64_t unkF0;
    uint64_t unkF8;
    uint64_t unk100;
    uint64_t unk108;
    uint64_t unk110;
    uint64_t unk118;
    uint64_t unk120;
    uint64_t unk128;
    uint64_t unk130;
    uint64_t unk138;
    uint64_t unk140;
    uint64_t unk148;
    uint64_t unk150;
    uint64_t unk158;
    uint64_t unk160;
    uint64_t unk168;
    uint64_t unk170;
    uint64_t unk178;
    uint64_t unk180;
    uint64_t unk188;
    uint64_t unk190;
    uint64_t unk198;
    uint64_t unk1A0;
    uint64_t unk1A8;
    uint64_t unk1B0;
    uint64_t unk1B8;
    uint64_t unk1C0;
    uint64_t unk1C8;
    uint64_t unk1D0;
    uint64_t unk1D8;
    uint64_t unk1E0;
    uint64_t unk1E8;
    uint64_t unk1F0;
    uint64_t unk1F8;
};

#endif // L2C_H
