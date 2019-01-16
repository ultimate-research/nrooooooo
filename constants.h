#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <map>
#include <vector>
#include <string>
#include <set>

extern std::set<uint32_t> last_crcs;
extern std::map<uint64_t, std::string> unhash;
extern std::map<uint32_t, std::string> unhash_parts;
extern std::map<uint64_t, std::string> status_funcs;

extern std::map<std::string, std::vector<std::string> > character_objects;
extern std::string agents[11];
extern std::string characters[89];
extern std::string status_func[23];
extern std::string fighter_status_kind[0x1A7];

void init_character_objects();

#endif // CONSTANTS_H
