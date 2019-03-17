#ifndef LUA_EMIT_H
#define LUA_EMIT_H

#include <stdint.h>
#include <string>
#include <vector>
#include <map>

#include "logging.h"

#define LUA_MAGIC 0x61754C1B

#pragma pack(push, 1)
typedef struct luac_header
{
    uint32_t magic;
    uint8_t version;
    uint8_t format;
    char data[6];
    uint8_t int_size;
    uint8_t sizet_size;
    uint8_t instr_size;
    uint8_t luaint_size;
    uint8_t luanum_size;
    uint64_t luaint_test;
    float luanum_test;
} luac_header;


typedef struct luac_Instruction
{
    union
    {
        uint32_t raw : 32;
        struct
        {
            uint32_t opcode : 6;
            uint32_t ax : 26;
        };
        struct
        {
            uint32_t op_ : 6;
            uint32_t a_ : 8;
            uint32_t bx : 18;
        };
        struct
        {
            uint32_t op : 6;
            uint32_t a : 8;
            uint32_t b : 9;
            uint32_t c : 9;
        };     
    };
} luac_Instruction;
#pragma pack(pop)

typedef struct luac_Constant
{
    uint8_t type;
    float number;
    uint64_t integer;
    char* string;
} luac_Constant;

typedef struct luac_Upvalue
{
    uint8_t a;
    uint8_t b;
} luac_Upval;

enum luac_ConstType : uint8_t
{
    luac_Nil = 0,
    luac_Boolean = 1,
    luac_Number = 2,
    luac_Integer = 3,
    luac_StrConst = 4,
    luac_LStrConst = 5
};

enum luac_Opcode : uint8_t
{
    luac_OpMOVE = 0,
    luac_OpLOADK = 1,
    luac_OpLOADKX = 2,
    luac_OpLOADBOOL = 3,
    luac_OpLOADNIL = 4,
    luac_OpGETUPVAL = 5,
    luac_OpGETTABUP = 6,
    luac_OpGETTABLE = 7,
    luac_OpSETTABUP = 8,
    luac_OpSETUPVAL = 9,
    luac_OpSETTABLE = 10,
    luac_OpNEWTABLE = 11,
    luac_OpSELF = 12,
    luac_OpADD = 13,
    luac_OpSUB = 14,
    luac_OpMUL = 15,
    luac_OpMOD = 16,
    luac_OpPOW = 17,
    luac_OpDIV = 18,
    luac_OpIDIV = 19,
    luac_OpBAND = 20,
    luac_OpBOR = 21,
    luac_OpBXOR = 22,
    luac_OpSHL = 23,
    luac_OpSHR = 24,
    luac_OpUNM = 25,
    luac_OpBNOT = 26,
    luac_OpNOT = 27,
    luac_OpLEN = 28,
    luac_OpCONCAT = 29,
    luac_OpJMP = 30,
    luac_OpEQ = 31,
    luac_OpLT = 32,
    luac_OpLE = 33,
    luac_OpTEST = 34,
    luac_OpTESTSET = 35,
    luac_OpCALL = 36,
    luac_OpTAILCALL = 37,
    luac_OpRETURN = 38,
    luac_OpFORLOOP = 39,
    luac_OpFORPREP = 40,
    luac_OpTFORCALL = 41,
    luac_OpTFORLOOP = 42,
    luac_OpSETLIST = 43,
    luac_OpCLOSURE = 44,
    luac_OpVARARG = 45,
    luac_OpEXTRAARG = 46
};

#define EmitOpABC(op) \
        void EmitOp##op(uint8_t a, uint16_t b, uint16_t c)\
        {\
            luac_Instruction instr = {.raw = 0};\
            instr.opcode = luac_Op##op;\
            instr.a = a;\
            instr.b = b;\
            instr.c = c;\
            instructions.push_back(instr);\
        }

#define EmitOpAB(op) \
        void EmitOp##op(uint8_t a, uint16_t b)\
        {\
            luac_Instruction instr = {.raw = 0};\
            instr.opcode = luac_Op##op;\
            instr.a = a;\
            instr.b = b;\
            instr.c = 0;\
            instructions.push_back(instr);\
        }

#define EmitOpAC(op) \
        void EmitOp##op(uint8_t a, uint16_t c)\
        {\
            luac_Instruction instr = {.raw = 0};\
            instr.opcode = luac_Op##op;\
            instr.a = a;\
            instr.b = 0;\
            instr.c = c;\
            instructions.push_back(instr);\
        }

#define EmitOpA(op) \
        void EmitOp##op(uint8_t a)\
        {\
            luac_Instruction instr = {.raw = 0};\
            instr.opcode = luac_Op##op;\
            instr.a = a;\
            instr.b = 0;\
            instr.c = 0;\
            instructions.push_back(instr);\
        }

#define EmitOp(op) \
        void EmitOp##op(void)\
        {\
            luac_Instruction instr = {.raw = 0};\
            instr.opcode = luac_Op##op;\
            instr.a = 0;\
            instr.b = 0;\
            instr.c = 0;\
            instructions.push_back(instr);\
        }

#define EmitOpABx(op) \
        void EmitOp##op(uint8_t a, uint32_t bx)\
        {\
            luac_Instruction instr = {.raw = 0};\
            instr.opcode = luac_Op##op;\
            instr.a = a;\
            instr.bx = bx;\
            instructions.push_back(instr);\
        }

#define EmitOpAx(op) \
        void EmitOp##op(uint32_t ax)\
        {\
            luac_Instruction instr = {.raw = 0};\
            instr.opcode = luac_Op##op;\
            instr.ax = ax;\
            instructions.push_back(instr);\
        }

class LuaBytecodeEmitter
{
private:
    std::string path;
    std::vector<uint8_t> emitted;
    std::vector<luac_Instruction> instructions;
    std::vector<luac_Constant> constants;
    std::vector<luac_Upvalue> upvalues;
    std::map<uint64_t, LuaBytecodeEmitter> function_emitters;

public:
    LuaBytecodeEmitter(std::string path = "");
    ~LuaBytecodeEmitter();
    
    void AddBlock(uint64_t id);
    
    void EmitLuacHeader();
    void BeginFunction(uint32_t line, uint32_t lastline, uint8_t params, bool is_vararg, uint8_t max_stacksize);
    void EmitFunctionHeader(uint32_t line, uint32_t lastline, uint8_t params, bool is_vararg, uint8_t max_stacksize);
    void FinalizeFunction();
    
    void Emit8(uint8_t val);
    void Emit16(uint16_t val);
    void Emit32(uint32_t val);
    void Emit64(uint64_t val);
    void EmitRaw(uint8_t* data, size_t size);

    EmitOpAB(MOVE)
    EmitOpABx(LOADK)
    EmitOpA(LOADKX)
    EmitOpABC(LOADBOOL)
    EmitOpAB(LOADNIL)
    EmitOpAB(GETUPVAL)
    EmitOpABC(GETTABUP)
    EmitOpABC(GETTABLE)
    EmitOpABC(SETTABUP)
    EmitOpAB(SETUPVAL)
    EmitOpABC(SETTABLE)
    EmitOpABC(NEWTABLE)
    EmitOpABC(SELF)
    
    EmitOpABC(ADD)
    EmitOpABC(SUB)
    EmitOpABC(MUL)
    EmitOpABC(MOD)
    EmitOpABC(POW)
    EmitOpABC(DIV)
    EmitOpABC(IDIV)
    EmitOpABC(BAND)
    EmitOpABC(BOR)
    EmitOpABC(BXOR)
    EmitOpABC(SHL)
    EmitOpABC(SHR)
    EmitOpAB(UNM)
    EmitOpAB(BNOT)
    EmitOpAB(NOT)
    EmitOpAB(LEN)
    
    EmitOpAB(CONCAT)
    
    EmitOpABx(JMP)
    EmitOpABC(EQ)
    EmitOpABC(LT)
    EmitOpABC(LE)
    
    EmitOpAC(TEST)
    EmitOpABC(TESTSET)
    
    EmitOpABC(CALL)
    EmitOpABC(TAILCALL)
    EmitOpAC(RETURN)

    EmitOpABx(FORLOOP)
    EmitOpABx(FORPREP)
    EmitOpAC(TFORCALL)
    EmitOpABx(TFORLOOP)

    EmitOpABC(SETLIST)
    EmitOpABx(CLOSURE)
    EmitOpAB(VARARG)
    EmitOpAx(EXTRAARG)
    
    void EmitUpvalue(uint8_t a, uint8_t b)
    {
        luac_Upvalue upval;
        upval.a = a;
        upval.b = b;

        upvalues.push_back(upval);
    }
    
    uint8_t* GetEmissions() const;
    size_t EmissionSize() const;
};

#endif // LUA_EMIT_H
