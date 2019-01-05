#ifndef L2C_H
#define L2C_H

enum L2CVarType
{
    L2C_bool = 1,
    L2C_number = 2,
    L2C_float = 3,
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
    
    bool as_bool()
    {
        return raw & 1;
    }
    
    uint64_t as_number()
    {
        return raw;
    }
    
    float as_float()
    {
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

#endif // L2C_H
