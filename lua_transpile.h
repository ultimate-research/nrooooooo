#ifndef LUA_TRANSPILE_H
#define LUA_TRANSPILE_H

#include <stdint.h>
#include <map>
#include <set>

#include "l2c.h"
#include "lua_emitter.h"

class LuaTranspiler
{
private:
    std::string path;
    std::map<uint64_t, std::set<L2C_Token> > tokens;
    uint64_t func;
    
    LuaBytecodeEmitter emitter;

public:
    LuaTranspiler(std::string path, std::map<uint64_t, std::set<L2C_Token> > tokens, uint64_t func) : path(path), tokens(tokens), func(func), emitter(path) 
    {
        emitter.EmitLuacHeader();
        emitter.BeginFunction(0, 0, 0, 1, 2);
        emitter.EmitOpRETURN(0, 1);
        emitter.EmitUpvalue(1, 0); // ENV
    }
    ~LuaTranspiler() 
    {
        emitter.FinalizeFunction();
    }
    
    
};

#endif // LUA_TRANSPILE_H
