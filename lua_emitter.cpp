#include "lua_emitter.h"

#include <stdio.h>
#include <stdlib.h>
#include <cstring>

LuaBytecodeEmitter::LuaBytecodeEmitter(std::string path)
{
    this->path = path;
    this->emitted = std::vector<uint8_t>();
    this->instructions = std::vector<luac_Instruction>();
    this->constants = std::vector<luac_Constant>();
    this->upvalues = std::vector<luac_Upvalue>();
    this->function_emitters = std::map<uint64_t, LuaBytecodeEmitter>();
}

LuaBytecodeEmitter::~LuaBytecodeEmitter() 
{
    if (path == "") return;

    FILE* f = fopen(path.c_str(), "wb");
    if (!f)
    {
        printf_error("Failed to open `%s'!\n", path.c_str());
        return;
    }

    fwrite(emitted.data(), 1, emitted.size(), f);
    fclose(f);
    printf_error("Wrote `%s'!\n", path.c_str());
}

void LuaBytecodeEmitter::AddBlock(uint64_t id)
{

}

void LuaBytecodeEmitter::EmitLuacHeader()
{
    luac_header header;
    header.magic = LUA_MAGIC;
    header.version = 0x53;
    header.format = 0;
    memcpy(header.data, "\x19\x93\r\n\x1a\n", 6);
    header.int_size = sizeof(uint32_t);
    header.sizet_size = sizeof(uint64_t);
    header.instr_size = sizeof(uint32_t);
    header.luaint_size = sizeof(uint64_t);
    header.luanum_size = sizeof(float);
    header.luaint_test = 0x5678;
    header.luanum_test = 370.5f;
    
    EmitRaw((uint8_t*)&header, sizeof(header));
    Emit8(1); // UpVals size?
    Emit8(0); // some debug str size
}

void LuaBytecodeEmitter::BeginFunction(uint32_t line, uint32_t lastline, uint8_t params, bool is_vararg, uint8_t max_stacksize)
{
    EmitFunctionHeader(line, lastline, params, is_vararg, max_stacksize);
    // some inits for instructions, constants, upvalues, function emitters
}

void LuaBytecodeEmitter::EmitFunctionHeader(uint32_t line, uint32_t lastline, uint8_t params, bool is_vararg, uint8_t max_stacksize)
{
    Emit32(line);
    Emit32(lastline);
    Emit8(params);
    Emit8(is_vararg ? 2 : 0);
    Emit8(max_stacksize);
}

void LuaBytecodeEmitter::FinalizeFunction()
{
    Emit32(instructions.size()); // num instructions
    
    for (auto& instr : instructions)
    {
        Emit32(instr.raw);
        //printf("%x\n", instr.raw);
    }
    
    Emit32(constants.size()); // num constants
    
    for (auto& c : constants)
    {
        Emit8(c.type);
        switch (c.type)
        {
            case luac_Nil:
                break;
            case luac_Boolean:
                Emit8(c.integer & 1);
                break;
            case luac_Number:
                Emit32(c.number);
                break;
            case luac_Integer:
                Emit64(c.integer);
                break;
                
            case luac_StrConst:
            case luac_LStrConst:
                if (c.string == NULL)
                {
                    Emit64(0);
                }
                else
                {
                    Emit64(strlen(c.string)+1);
                    for (size_t i = 0; i < strlen(c.string)+1; i++)
                    {
                        Emit8(c.string[i]);
                    }
                }
                break;
        }
    }
    
    Emit32(upvalues.size()); // num upvalues
    
    for (auto& upval : upvalues)
    {
        Emit8(upval.a);
        Emit8(upval.b);
    }

    Emit32(function_emitters.size()); // num function prototypes
    
    for (auto& [k, f] : function_emitters)
    {
        f.FinalizeFunction();
        EmitRaw(f.GetEmissions(), f.EmissionSize());
    }
    
    // debug stuff
    Emit32(0);
    Emit32(0);
    Emit32(0);
    
    //TODO: prevent emitter from emitting any more
}

void LuaBytecodeEmitter::Emit8(uint8_t val)
{
    EmitRaw((uint8_t*)&val, sizeof(uint8_t));
}

void LuaBytecodeEmitter::Emit16(uint16_t val)
{
    EmitRaw((uint8_t*)&val, sizeof(uint16_t));
}

void LuaBytecodeEmitter::Emit32(uint32_t val)
{
    EmitRaw((uint8_t*)&val, sizeof(uint32_t));
}

void LuaBytecodeEmitter::Emit64(uint64_t val)
{
    EmitRaw((uint8_t*)&val, sizeof(uint64_t));
}

void LuaBytecodeEmitter::EmitRaw(uint8_t* data, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        emitted.push_back(data[i]);
    }
}

uint8_t* LuaBytecodeEmitter::GetEmissions() const
{
    return (uint8_t*)emitted.data();
}

size_t LuaBytecodeEmitter::EmissionSize() const
{
    return emitted.size();
}
