#include "l2c.h"

#include "main.h"

std::string L2C_Token::to_string(uint64_t rel) const
{
    char tmp[256];
    std::string out = "";
    for (size_t i = 0; i < fork_hierarchy.size() - 1; i++)
    {
        out += "  ";
    }

    //printf("%s%" PRIx64 " ", (rel ? "+" : ""), pc - rel);
    //if (rel)
    //    printf("b:%" PRIx64 "", blocks[rel].hash());
    //out += (rel ? "+" : "");
    //snprintf(tmp, 256, "%" PRIx64 " ", pc);
    //out += std::string(tmp);

    //printf("%s", fork_hierarchy_str().c_str());
    out += " " + str;

    if (args.size())
        out += " args ";

    bool is_exit = false;
    if (str == "SUB_BRANCH" || str == "SUB_GOTO" || str == "DIV_FALSE" || str == "DIV_TRUE" || str == "CONV" || str == "BLOCK_MERGE" || str == "SPLIT_BLOCK_MERGE")
        is_exit = true;

    for (size_t i = 0; i < args.size(); i++)
    {
        if (is_exit && rel)
        {
            // Address difference
            /*bool neg = false;
            uint64_t val = args[i] - pc;
            if ((*(int64_t*)&val) < 0)
            {
                val = (val ^ ~0) + 1;
                neg = true;
            }

            snprintf(tmp, 256, "%s0x%" PRIx64 "", (neg ? "-" : "+"), val);*/
            
            // Hash
            snprintf(tmp, 256, "b:%" PRIx64 "", blocks[args[i]].hash());
            out += std::string(tmp);
        }
        else
        {
            snprintf(tmp, 256, "0x%" PRIx64 "", args[i]);
            out += std::string(tmp);
            
            if (unhash[args[i]] != "")
                out += " (" + unhash[args[i]] + ")";
        }

        if (i < args.size() - 1)
            out += ", ";
    }

    if (fargs.size())
        out += " fargs ";

    for (auto i = 0; i < fargs.size(); i++)
    {
        snprintf(tmp, 256, "%f", fargs[i]);
        out += std::string(tmp);
        if (i < fargs.size() - 1)
            out += ", ";
    }

    out += "\n";
    return out;
}
