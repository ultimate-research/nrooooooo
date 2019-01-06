#ifndef L2C_H
#define L2C_H

#include <vector>

struct Hash40
{
    uint64_t hash : 40;
};

struct L2C_Token
{
    uint64_t pc;
    std::vector<int> fork_heirarchy;
    std::string func;
    bool is_function;
    std::vector<uint64_t> args;
    std::vector<float> fargs;
    
    bool operator<(const L2C_Token& comp) const
    {
        if (pc == comp.pc) return fork_heirarchy.size() > comp.fork_heirarchy.size();
 
        return pc < comp.pc;
    }
};

enum L2CVarType
{
    L2C_bool = 1,
    L2C_integer = 2,
    L2C_number = 3,
    L2C_pointer = 4,
    L2C_table = 5,
    L2C_inner_function = 6,
    L2C_hash = 7,
    L2C_string = 8,
};

struct L2CTable
{
    uint32_t refcnt;
};

struct L2CInnerFunctionBase
{
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
        //std::string raw_string;
    };
    uint64_t string_1;
    uint64_t string_2;
    
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
        type = L2C_pointer;
        raw_float = val;
    }
    
    bool as_bool()
    {
        return raw & 1;
    }
    
    int as_integer()
    {
        return (int)raw;
    }
    
    float as_number()
    {
        if (type == L2C_integer)
        {
            return (float)as_integer();
        }

        return raw_float;
    }
    
    void* as_pointer()
    {
        return raw_pointer;
    }
    
    L2CTable* as_table()
    {
        return raw_table;
    }
    
    L2CInnerFunctionBase* as_inner_function()
    {
        return raw_innerfunc;
    }
    
    uint64_t as_hash()
    {
        return raw & 0xFFFFFFFFFF;
    }
    
    /*const char* as_string()
    {
        return raw_string.c_str();
    }*/
};

struct L2CAgent
{
    uint64_t unk0;
    uint64_t unk8;
    uint64_t unk10;
    uint64_t unk18;
    uint64_t unk20;
    uint64_t unk28;
    uint64_t unk30;
    uint64_t unk38;
    uint64_t unkptr40;
};

struct L2CUnk40
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
    uint64_t unkptr50;
};

struct L2CUnk40ptr50
{
    uint64_t vtable;
};

struct L2CUnk40ptr50Vtable
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
