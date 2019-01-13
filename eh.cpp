#include "eh.h"

#include <cstring>
#include <cstdio>
#include <inttypes.h>

struct eh_frame_hdr_entry
{
    int32_t initial_loc;
    int32_t fde_ptr;
};

struct eh_frame_hdr
{
    uint8_t version;
    uint8_t eh_frame_ptr_enc;
    uint8_t fde_count_enc;
    uint8_t table_enc;
    uint32_t eh_frame_ptr;
    uint32_t fde_count;
    struct eh_frame_hdr_entry entries[];
};

#pragma pack(push, 1)

struct fde_hdr
{
    uint32_t size;
    uint32_t cie_ptr;
    int32_t initial_loc;
    uint32_t range;
    uint8_t aug_len;
};

struct cie_hdr
{
    uint32_t size;
    uint32_t cie_id;
    uint8_t version;
};

#pragma pack(pop)

#define DW_EH_PE_ptr		0x00
#define DW_EH_PE_uleb128    0x01
#define DW_EH_PE_udata2     0x02
#define DW_EH_PE_udata4		0x03
#define DW_EH_PE_udata8		0x04
#define DW_EH_PE_sleb128    0x09
#define DW_EH_PE_sdata2     0x0a
#define DW_EH_PE_sdata4		0x0b
#define DW_EH_PE_sdata8		0x0c

#define DW_EH_PE_absptr		0x00
#define DW_EH_PE_pcrel		0x10
#define DW_EH_PE_textrel    0x20
#define DW_EH_PE_datarel    0x30
#define DW_EH_PE_funcrel    0x40
#define DW_EH_PE_aligned    0x50

#define DW_EH_PE_indirect   0x80
#define DW_EH_PE_omit		0xff

uint64_t read_leb128(uint8_t* data, uint64_t* offset, bool is_signed)
{
    uint64_t retval = 0;
    uint64_t shift = 0;
    uint8_t b;
    
    uint64_t addr = *offset;

    while (1)
    {
        b = data[addr++];
        retval |= ((b & 0x7F) << shift);
        shift += 7;

        if (shift > 64)
            return -1;

        if (b & 0x80)
            continue;

        break;
    }
    
    *offset = addr;

    if (is_signed && (b & 0x40))
    {
        retval |= (~0 << shift);
    }

    return retval;
}

uint64_t read_uleb128(uint8_t* data, uint64_t* offset)
{
    return read_leb128(data, offset, false);
}

int64_t read_sleb128(uint8_t* data, uint64_t* offset)
{
    uint64_t val = read_leb128(data, offset, true);
    return *(int64_t*)&val;
}

uint64_t encoded_ptr_size(uint8_t encoding)
{
    uint8_t lower;
    lower = encoding & 0xF;
    
    if (lower == DW_EH_PE_uleb128 || lower == DW_EH_PE_sleb128)
    {
        return sizeof(uint8_t);
    }
    else if (lower == DW_EH_PE_udata2 || lower == DW_EH_PE_sdata2)
    {
        return sizeof(uint16_t);
    }
    else if (lower == DW_EH_PE_udata4 || lower == DW_EH_PE_sdata4)
    {
        return sizeof(uint32_t);
    }
    else if (lower == DW_EH_PE_udata8 || lower == DW_EH_PE_sdata8 || lower == DW_EH_PE_ptr)
    {
        return sizeof(uint64_t);
    }
    
    return 0;
}

uint64_t read_encoded_ptr(uint8_t encoding, uint8_t* data, uint64_t* offset)
{
    if (encoding == DW_EH_PE_omit) return -1;
    
    uint64_t rel_offset = *offset;
    
    uint8_t upper, lower;
    upper = encoding & 0x70;
    lower = encoding & 0xF;
    
    bool is_u64 = false;
    int64_t sval = 0;
    uint64_t val = 0;
    if (lower == DW_EH_PE_uleb128)
    {
        val = read_uleb128(data, offset);
    }
    else if (lower == DW_EH_PE_sleb128)
    {
        sval = read_sleb128(data, offset);
    }
    else if (lower == DW_EH_PE_udata2)
    {
        val = *(uint16_t*)&data[*offset];
        *offset += sizeof(uint16_t);
    }
    else if (lower == DW_EH_PE_sdata2)
    {
        sval = *(int16_t*)&data[*offset];
        *offset += sizeof(int16_t);
    }
    else if (lower == DW_EH_PE_udata4)
    {
        val = *(uint32_t*)&data[*offset];
        *offset += sizeof(uint32_t);
    }
    else if (lower == DW_EH_PE_sdata4)
    {
        sval = *(int32_t*)&data[*offset];
        *offset += sizeof(int32_t);
    }
    else if (lower == DW_EH_PE_udata8 || lower == DW_EH_PE_ptr)
    {
        val = *(uint64_t*)&data[*offset];
        *offset += sizeof(uint64_t);
    }
    else if (lower == DW_EH_PE_sdata8)
    {
        sval = *(int64_t*)&data[*offset];
        *offset += sizeof(int64_t);
    }
    
    uint64_t retval = 0;
    if (upper == DW_EH_PE_absptr || upper == DW_EH_PE_textrel)
    {
        retval = (sval ? sval : val);
    }
    else if (upper == DW_EH_PE_pcrel)
    {
        retval = rel_offset + (sval ? sval : val);
    }
    else
    {
        printf("unknown upper %x\n", upper);
        return -1;
    }
    
    //printf("%x -> %x %x %llx %llx %llx %llx %x\n", encoding, upper, lower, retval, sval, val, offset, encoded_ptr_size(encoding));
    
    if (encoding & DW_EH_PE_indirect)
        retval = *(uint64_t*)&data[retval];

    //
    
    return retval;
}

int parse_cfa(uint8_t* data)
{
    uint64_t i = 0;
    uint8_t instr = data[i++];
    uint8_t instr_upper = instr >> 6;
    uint8_t instr_lower = instr & 0x3F;

    if (instr_upper == 1)
    {
        printf("DW_CFA_advance_loc(%x)\n", instr_lower);
    }
    else if (instr_upper == 2)
    {
        uint64_t offset = read_encoded_ptr(DW_EH_PE_uleb128, data, &i);
        printf("DW_CFA_offset(%x, %" PRIx64 ")\n", instr_lower, offset);
    }
    else if (instr_upper == 3)
    {
        printf("DW_CFA_restore(%x)\n", instr_lower);
    }
    else if (instr_upper == 0 && instr_lower == 1)
    {
        uint64_t offset = *(uint64_t*)&data[i];
        i += sizeof(uint64_t);

        printf("DW_CFA_set_loc(%" PRIx64 ")\n", offset);
    }
    else if (instr_upper == 0 && instr_lower == 2)
    {
        uint8_t offset = *(uint8_t*)&data[i];
        i += sizeof(uint8_t);

        printf("DW_CFA_advance_loc1(%" PRIx64 ")\n", offset);
    }
    else if (instr_upper == 0 && instr_lower == 3)
    {
        uint16_t offset = *(uint16_t*)&data[i];
        i += sizeof(uint16_t);

        printf("DW_CFA_advance_loc2(%" PRIx64 ")\n", offset);
    }
    else if (instr_upper == 0 && instr_lower == 4)
    {
        uint32_t offset = *(uint32_t*)&data[i];
        i += sizeof(uint32_t);

        printf("DW_CFA_advance_loc4(%" PRIx64 ")\n", offset);
    }
    else if (instr_upper == 0 && instr_lower == 5)
    {
        uint64_t reg = read_encoded_ptr(DW_EH_PE_uleb128, data, &i);
        uint64_t offset = read_encoded_ptr(DW_EH_PE_uleb128, data, &i);

        printf("DW_CFA_offset_extended(%" PRIx64 ", %" PRIx64 ")\n", reg, offset);
    }
    else if (instr_upper == 0 && instr_lower == 6)
    {
        uint64_t reg = read_encoded_ptr(DW_EH_PE_uleb128, data, &i);

        printf("DW_CFA_restore_extended(%" PRIx64 ")\n", reg);
    }
    else if (instr_upper == 0 && instr_lower == 7)
    {
        uint64_t reg = read_encoded_ptr(DW_EH_PE_uleb128, data, &i);

        printf("DW_CFA_undefined(%" PRIx64 ")\n", reg);
    }
    else if (instr_upper == 0 && instr_lower == 8)
    {
        uint64_t reg = read_encoded_ptr(DW_EH_PE_uleb128, data, &i);

        printf("DW_CFA_save_value(%" PRIx64 ")\n", reg);
    }
    else if (instr_upper == 0 && instr_lower == 9)
    {
        uint64_t reg = read_encoded_ptr(DW_EH_PE_uleb128, data, &i);
        uint64_t offset = read_encoded_ptr(DW_EH_PE_uleb128, data, &i);

        printf("DW_CFA_register(%" PRIx64 ", %" PRIx64 ")\n", reg, offset);
    }
    else if (instr_upper == 0 && instr_lower == 0xa)
    {
        printf("DW_CFA_remember_state()\n");
    }
    else if (instr_upper == 0 && instr_lower == 0xb)
    {
        printf("DW_CFA_store_state()\n");
    }
    else if (instr_upper == 0 && instr_lower == 0xc)
    {
        uint64_t reg = read_encoded_ptr(DW_EH_PE_uleb128, data, &i);
        uint64_t offset = read_encoded_ptr(DW_EH_PE_uleb128, data, &i);

        printf("DW_CFA_def_cfa(%" PRIx64 ", %" PRIx64 ")\n", reg, offset);
    }
    else if (instr_upper == 0 && instr_lower == 0xd)
    {
        uint64_t reg = read_encoded_ptr(DW_EH_PE_uleb128, data, &i);

        printf("DW_CFA_def_cfa_register(%" PRIx64 ")\n", reg);
    }
    else if (instr_upper == 0 && instr_lower == 0xe)
    {
        uint64_t offset = read_encoded_ptr(DW_EH_PE_uleb128, data, &i);

        printf("DW_CFA_def_cfa_offset(%" PRIx64 ")\n", offset);
    }
    else if (instr_upper == 0 && instr_lower == 0)
    {
        printf("DW_CFA_nop()\n");
    }
    else if (instr_upper == 0 && instr_lower == 0x14)
    {
        uint64_t reg = read_encoded_ptr(DW_EH_PE_uleb128, data, &i);
        uint64_t offset = read_encoded_ptr(DW_EH_PE_uleb128, data, &i);
        printf("DW_CFA_val_offset(%" PRIx64 ", %" PRIx64 ")\n", reg, offset);
    }
    else if (instr_upper == 0 && instr_lower == 0x1c)
    {
        printf("DW_CFA_lo_user()\n");
    }
    else if (instr_upper == 0 && instr_lower == 0x3f)
    {
        printf("DW_CFA_hi_user()\n");
    }
    else
    {
        printf("unk %02x\n", instr);
    }
    
    return i;
}

int parse_lsda(uint64_t lsda_addr, uint64_t func_addr, uint8_t* base)
{
    uint64_t i = lsda_addr;
    
    uint64_t start = lsda_addr;
    uint64_t lpstart_addr, ttype_addr, callsites_addr, callsites_end, action_table_addr = 0;
    
    uint8_t lpstart_enc = base[i++];
    if (lpstart_enc != DW_EH_PE_omit)
    {
        lpstart_addr = read_encoded_ptr(lpstart_enc, base, &i);
        
        printf("lpstart enc %x addr %" PRIx64 "\n", lpstart_enc, lpstart_addr);
    }
    
    uint8_t ttype_enc = base[i++];
    if (ttype_enc != DW_EH_PE_omit)
    {
        ttype_addr = read_encoded_ptr(DW_EH_PE_uleb128 | DW_EH_PE_pcrel, base, &i);
        
        printf("ttype enc %x addr %" PRIx64 "\n", ttype_enc, ttype_addr);
    }

    uint8_t callsites_enc = base[i++];
    if (callsites_enc != DW_EH_PE_omit)
    {
        action_table_addr = read_encoded_ptr(DW_EH_PE_uleb128 | DW_EH_PE_pcrel, base, &i);
    }
    
    callsites_addr = i;
    callsites_end = i;
    if (action_table_addr)
        callsites_end = action_table_addr;
    
    printf("callsites enc %x start %" PRIx64 " end %" PRIx64 "\n", callsites_enc, callsites_addr, callsites_end);
    
    while (i < callsites_end)
    {
        uint64_t start, len, lp, action;
        start = read_encoded_ptr(callsites_enc, base, &i);
        len = read_encoded_ptr(callsites_enc & 0xF, base, &i);
        lp = read_encoded_ptr(callsites_enc, base, &i);
        action = read_encoded_ptr(DW_EH_PE_uleb128, base, &i);
        
        printf("    addr %08" PRIx64 " len %08" PRIx64 " lp %08" PRIx64 " action %08" PRIx64 "\n", func_addr + start, len, lp ? func_addr + lp : 0, action);
    }
    
    return i;
}

void parse_eh(void* base, uint64_t unwind_start)
{
    struct eh_frame_hdr* eh_header = (struct eh_frame_hdr*)(base + unwind_start);
    void* eh_sect = (void*)(&eh_header->eh_frame_ptr + eh_header->eh_frame_ptr);
    uint32_t eh_header_offset = unwind_start;
    uint32_t eh_offset = eh_header_offset + eh_header->eh_frame_ptr + 4;

    printf("%x %x %x\n", eh_header_offset, eh_offset, eh_header->fde_count);
    for (int i = 0; i < eh_header->fde_count; i++)
    {
        uint32_t initial_loc_abs = eh_header_offset + eh_header->entries[i].initial_loc;
        uint32_t fde_ptr_abs = eh_header_offset + eh_header->entries[i].fde_ptr;
        
        struct fde_hdr* fde = (struct fde_hdr*)(base + fde_ptr_abs);
        uint32_t cie_ptr_abs = fde_ptr_abs - fde->cie_ptr + 4;
        
        struct cie_hdr* cie = (struct cie_hdr*)(base + cie_ptr_abs);
        
        printf("func %x size %x fde %x cie %x, %x\n", initial_loc_abs,  fde->range, fde_ptr_abs, cie_ptr_abs, cie->size);
        
        uint64_t cie_pos = cie_ptr_abs + sizeof(struct cie_hdr);
        char* aug_str = (char*)base + cie_pos;
        cie_pos += strlen(aug_str)+1;
        
        uint8_t code_align, data_align, return_reg, aug_data_len, lsda_encoding;
        code_align = read_encoded_ptr(DW_EH_PE_uleb128, (uint8_t*)base, &cie_pos);
        data_align = read_encoded_ptr(DW_EH_PE_uleb128, (uint8_t*)base, &cie_pos);
        return_reg = read_encoded_ptr(DW_EH_PE_uleb128, (uint8_t*)base, &cie_pos);
        int aug_start = cie_pos;
        
        for (int i = 0; i < strlen(aug_str); i++)
        {
            if (aug_str[i] == 'z')
            {
                aug_data_len = read_encoded_ptr(DW_EH_PE_uleb128, (uint8_t*)base, &cie_pos);
                printf("augmentation data len: %x\n", aug_data_len);
            }
            else if (aug_str[i] == 'P')
            {
                uint8_t personality_encoding = *((uint8_t*)base + cie_pos++);
                uint64_t personality_ptr = read_encoded_ptr(personality_encoding, (uint8_t*)base, &cie_pos);
 
                printf("Personality routine: enc %x, func %" PRIx64 "\n", personality_encoding, personality_ptr);
            }
            else if (aug_str[i] == 'L')
            {
                lsda_encoding = *((uint8_t*)base + cie_pos++);
                printf("LSDA encoding: %x\n", lsda_encoding);
            }
            else if (aug_str[i] == 'R')
            {
                uint8_t fde_encoding = *((uint8_t*)base + cie_pos++);
                printf("FDE encoding: %x\n", fde_encoding);
            }
            else
            {
                printf("unk %c\n", aug_str[i]);
            }
        }
        
        printf("cie instrs:\n");
        for (int j = cie_pos; j < cie_ptr_abs + cie->size + 4; j)
        {
            j += parse_cfa((uint8_t*)base + j);
        }
        printf("\n");
        
        // LSDA
        uint64_t fde_pos = fde_ptr_abs + sizeof(struct fde_hdr);
        if (fde->aug_len)
        {
            uint64_t lsda_ptr = read_encoded_ptr(lsda_encoding, (uint8_t*)base, &fde_pos);
            printf("fde aug data (LSDA): %llx\n", lsda_ptr);
            
            parse_lsda(lsda_ptr, initial_loc_abs, (uint8_t*)base);
        }

        printf("fde instrs:\n");
        for (int j = fde_pos + fde->aug_len; j < fde_ptr_abs + fde->size + 4; j)
        {
            j += parse_cfa((uint8_t*)base + j);
        }
        printf("\n\n");
    }
}
