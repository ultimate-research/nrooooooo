#include "l2c.h"

#include "main.h"

void L2C_Token::print(uint64_t rel) const
{
    for (size_t i = 0; i < fork_hierarchy.size() - 1; i++)
    {
        printf("  ");
    }

    //printf("%s%" PRIx64 " ", (rel ? "+" : ""), pc - rel);
    //if (rel)
    //    printf("b:%" PRIx64 "", blocks[rel].hash());
    printf("%s%" PRIx64 " ", (rel ? "+" : ""), pc - rel);

    //printf("%s", fork_hierarchy_str().c_str());
    printf(" %s", str.c_str());

    if (args.size())
        printf(" args ");

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

            printf("%s0x%" PRIx64 "", (neg ? "-" : "+"), val);*/
            
            // Hash
            printf("b:%" PRIx64 "", blocks[args[i]].hash());
        }
        else
        {
            printf("0x%" PRIx64 "", args[i]);
        }

        if (i < args.size() - 1)
            printf(", ");
    }

    if (fargs.size())
        printf(" fargs ");

    for (auto i = 0; i < fargs.size(); i++)
    {
        printf("%f", fargs[i]);
        if (i < fargs.size() - 1)
            printf(", ");
    }

    printf("\n");
}
