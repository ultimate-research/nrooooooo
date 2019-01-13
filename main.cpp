#include "main.h"

#include <string.h>
#include <time.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <list>
#include <algorithm>
#include <elf.h>
#include <cxxabi.h>
#include "crc32.h"
#include "uc_inst.h"
#include "logging.h"
#include "eh.h"

std::map<uint64_t, std::string> unhash;

int instance_id_cnt = 0;
int imports_size = 0;
std::map<std::string, uint64_t> unresolved_syms;
std::map<uint64_t, std::string> unresolved_syms_rev;
std::map<std::string, uint64_t> resolved_syms;
std::map<std::pair<uint64_t, uint64_t>, uint64_t> function_hashes;
std::map<uint64_t, std::set<L2C_Token> > tokens;
std::map<uint64_t, bool> converge_points;
std::map<uint64_t, L2C_CodeBlock> blocks;

std::map<uint64_t, bool> is_goto_dst;
std::map<uint64_t, bool> is_fork_origin;

std::map<uint64_t, uint64_t> hash_cheat;
std::map<uint64_t, uint64_t> hash_cheat_rev;
uint64_t hash_cheat_ptr;

bool syms_scanned = false;
bool trace_code = true;

std::map<std::string, std::vector<std::string> > character_objects;

std::string agents[] = { "status_script", "animcmd_effect", "animcmd_effect_share", "animcmd_expression", "animcmd_expression_share", "animcmd_game", "animcmd_game_share", "animcmd_sound", "animcmd_sound_share", "ai_action", "ai_mode" };

std::string characters[] = {
    "bayonetta",
    "captain",
    "chrom",
    "cloud",
    "daisy",
    "dedede",
    "diddy",
    "donkey",
    "duckhunt",
    "falco",
    "fox",
    "fushigisou",
    "gamewatch",
    "ganon",
    "gaogaen",
    "gekkouga",
    "ice_climber",
    "ike",
    "inkling",
    "kamui",
    "ken",
    "kirby",
    "koopa",
    "koopag",
    "koopajr",
    "krool",
    "link",
    "littlemac",
    "lizardon",
    "lucario",
    "lucas",
    "lucina",
    "luigi",
    "mario",
    "mariod",
    "marth",
    "metaknight",
    "mewtwo",
    "miienemyf",
    "miienemyg",
    "miienemys",
    "miifighter",
    "miigunner",
    "miiswordsman",
    "murabito",
    "nana",
    "ness",
    "none",
    "pacman",
    "palutena",
    "peach",
    "pfushigisou",
    "pichu",
    "pikachu",
    "pikmin",
    "pit",
    "pitb",
    "plizardon",
    "popo",
    "ptrainer",
    "purin",
    "pzenigame",
    "random",
    "reflet",
    "richter",
    "ridley",
    "robot",
    "rockman",
    "rosetta",
    "roy",
    "ryu",
    "samus",
    "samusd",
    "sheik",
    "shizue",
    "shulk",
    "simon",
    "snake",
    "sonic",
    "szerosuit",
    "toonlink",
    "wario",
    "wiifit",
    "wolf",
    "yoshi",
    "younglink",
    "zelda",
    "zenigame",
    "common",
};

std::string status_func[] = {
    "STATUS_PRE",
    "STATUS_MAIN",
    "STATUS_END",
    "INIT_STATUS",
    "EXEC_STATUS",
    "EXEC_STOP",
    "EXEC_STATUS_POST",
    "EXIT_STATUS",
    "MAP_CORRECTION",
    "FIX_CAMERA",
    "FIX_POS_SLOW",
    "CHECK_DAMAGE",
    "CHECK_ATTACK",
    "ON_CHANGE_LR",
    "LEAVE_STOP",
    "NOTIFY_EVENT_GIMMICK",
    "CALC_PARAM",
    "RESERVE1",
    "RESERVE2",
    "RESERVE3",
    "RESERVE4",
    "RESERVE5",
    "LUA_SCRIPT_STATUS_FUNC_MAX",
};

std::string fighter_status_kind[] = {
    "NONE", // -1
    "WAIT", // 0
    "WALK",
    "WALK_BRAKE",
    "DASH",
    "RUN",
    "RUN_BRAKE",
    "TURN",
    "TURN_DASH",
    "TURN_RUN",
    "TURN_RUN_BRAKE",
    "JUMP_SQUAT",
    "JUMP",
    "JUMP_AERIAL",
    "FLY",
    "FALL",
    "FALL_AERIAL",
    "FALL_SPECIAL",
    "SQUAT",
    "SQUAT_WAIT",
    "SQUAT_F",
    "SQUAT_B",
    "SQUAT_RV",
    "LANDING",
    "LANDING_LIGHT",
    "LANDING_ATTACK_AIR",
    "LANDING_FALL_SPECIAL",
    "LANDING_DAMAGE_LIGHT",
    "GUARD_ON",
    "GUARD",
    "GUARD_OFF",
    "GUARD_DAMAGE",
    "ESCAPE",
    "ESCAPE_F",
    "ESCAPE_B",
    "ESCAPE_AIR",
    "ESCAPE_AIR_SLIDE",
    "REBOUND_STOP",
    "REBOUND",
    "REBOUND_JUMP",
    "ATTACK",
    "ATTACK_100",
    "ATTACK_DASH",
    "ATTACK_S3",
    "ATTACK_HI3",
    "ATTACK_LW3",
    "ATTACK_S4_START",
    "ATTACK_S4_HOLD",
    "ATTACK_S4",
    "ATTACK_LW4_START",
    "ATTACK_LW4_HOLD",
    "ATTACK_LW4",
    "ATTACK_HI4_START",
    "ATTACK_HI4_HOLD",
    "ATTACK_HI4",
    "ATTACK_AIR",
    "CATCH",
    "CATCH_PULL",
    "CATCH_DASH",
    "CATCH_DASH_PULL",
    "CATCH_TURN",
    "CATCH_WAIT",
    "CATCH_ATTACK",
    "CATCH_CUT",
    "CATCH_JUMP",
    "THROW",
    "CAPTURE_PULLED",
    "CAPTURE_WAIT",
    "CAPTURE_DAMAGE",
    "CAPTURE_CUT",
    "CAPTURE_JUMP",
    "THROWN",
    "DAMAGE",
    "DAMAGE_AIR",
    "DAMAGE_FLY",
    "DAMAGE_FLY_ROLL",
    "DAMAGE_FLY_METEOR",
    "DAMAGE_FLY_REFLECT_LR",
    "DAMAGE_FLY_REFLECT_U",
    "DAMAGE_FLY_REFLECT_D",
    "DAMAGE_FALL",
    "DOWN",
    "DOWN_SPOT",
    "DOWN_CONTINUE",
    "DOWN_WAIT",
    "DOWN_WAIT_CONTINUE",
    "DOWN_EAT",
    "LAY_DOWN",
    "DOWN_STAND",
    "DOWN_STAND_FB",
    "DOWN_STAND_ATTACK",
    "DOWN_DAMAGE",
    "DOWN_REFLECT_LR",
    "SHIELD_BREAK_FLY",
    "SHIELD_BREAK_FALL",
    "SHIELD_BREAK_DOWN",
    "FURAFURA_STAND",
    "FURAFURA",
    "FURAFURA_END",
    "DAMAGE_SONG_START",
    "DAMAGE_SONG",
    "DAMAGE_SONG_FALL",
    "DAMAGE_SONG_END",
    "BIND",
    "PASSIVE",
    "PASSIVE_FB",
    "PASSIVE_WALL",
    "PASSIVE_WALL_JUMP",
    "PASSIVE_CEIL",
    "STOP_WALL",
    "STOP_CEIL",
    "WALL_JUMP",
    "ATTACH_WALL",
    "ATTACH_WALL_WAIT",
    "DETACH_WALL",
    "DETACH_WALL_FALL",
    "DETACH_WALL_JUMP",
    "PASS",
    "CLIFF_CATCH_MOVE",
    "CLIFF_CATCH",
    "CLIFF_WAIT",
    "CLIFF_ATTACK",
    "CLIFF_CLIMB",
    "CLIFF_ESCAPE",
    "CLIFF_JUMP1",
    "CLIFF_JUMP2",
    "CLIFF_JUMP3",
    "OTTOTTO",
    "OTTOTTO_WAIT",
    "MISS_FOOT",
    "GLIDE_START",
    "GLIDE",
    "GLIDE_LANDING",
    "GLIDE_ATTACK",
    "GLIDE_END",
    "SLIP",
    "SLIP_DAMAGE",
    "SLIP_WAIT",
    "SLIP_STAND",
    "SLIP_STAND_ATTACK",
    "SLIP_STAND_F",
    "SLIP_STAND_B",
    "ITEM_LIGHT_PICKUP",
    "ITEM_HEAVY_PICKUP",
    "ITEM_THROW",
    "ITEM_THROW_DASH",
    "ITEM_LIFT_WAIT",
    "ITEM_LIFT_TURN",
    "ITEM_LIFT_WALK",
    "ITEM_THROW_HEAVY",
    "ITEM_SWING",
    "ITEM_SWING_S3",
    "ITEM_SWING_S4_START",
    "ITEM_SWING_S4",
    "ITEM_SWING_S4_HOLD",
    "ITEM_SWING_DASH",
    "ITEM_SHOOT_WAIT",
    "ITEM_SHOOT_WALK_F",
    "ITEM_SHOOT_WALK_BRAKE_F",
    "ITEM_SHOOT_WALK_B",
    "ITEM_SHOOT_WALK_BRAKE_B",
    "ITEM_SHOOT_TURN",
    "ITEM_SHOOT_JUMP_SQUAT",
    "ITEM_SHOOT_JUMP",
    "ITEM_SHOOT_JUMP_AERIAL",
    "ITEM_SHOOT_FLY",
    "ITEM_SHOOT_AIR",
    "ITEM_SHOOT_LANDING",
    "ITEM_SCREW_JUMP",
    "ITEM_SCREW_JUMP_AERIAL",
    "ITEM_SCREW_FALL",
    "ITEM_ASSIST_HOIST",
    "SWIM_DIVE",
    "SWIM_RISE",
    "SWIM_UP",
    "SWIM_WAIT",
    "SWIM",
    "SWIM_END",
    "SWIM_TURN",
    "SWIM_JUMP",
    "SWIM_DROWN",
    "SWIM_DROWN_OUT",
    "DEAD",
    "REBIRTH",
    "PLATE_WAIT",
    "TREAD_JUMP",
    "TREAD_DAMAGE",
    "TREAD_DAMAGE_RV",
    "TREAD_DAMAGE_AIR",
    "TREAD_FALL",
    "CLUNG_GANON",
    "CATCHED_GANON",
    "CATCHED_AIR_GANON",
    "CATCHED_AIR_FALL_GANON",
    "CATCHED_AIR_END_GANON",
    "CATCHED_CUT_GANON",
    "CLUNG_CAPTAIN",
    "KOOPA_DIVED",
    "SHOULDERED_DONKEY_START",
    "SHOULDERED_DONKEY",
    "SHOULDERED_DONKEY_THROWN",
    "BURY",
    "BURY_WAIT",
    "BURY_JUMP",
    "ICE",
    "ICE_JUMP",
    "GIMMICK_DOOR",
    "GIMMICK_BARREL",
    "GIMMICK_SPRING",
    "GIMMICK_SPRING_JUMP",
    "GIMMICK_SPRING_BACK",
    "GIMMICK_PIPE",
    "GIMMICK_TORNADO",
    "GIMMICK_FISH_CAPTURE",
    "GIMMICK_DRUM",
    "WARPSTAR",
    "WARPSTAR_JUMP",
    "DRAGOON_RIDE",
    "HAMMER_WAIT",
    "HAMMER_WALK",
    "HAMMER_TURN",
    "HAMMER_JUMP_SQUAT",
    "HAMMER_JUMP",
    "HAMMER_FALL",
    "HAMMER_LANDING",
    "LINK_FINAL",
    "LINK_FINAL_ARROW_HIT",
    "PIT_FALL",
    "THROW_KIRBY",
    "BIG",
    "SMALL",
    "SWALLOWED",
    "SWALLOWED_CANCEL",
    "SWALLOWED_CANCELED",
    "SWALLOWED_CAPTURE",
    "SWALLOWED_DRINK",
    "SWALLOWED_THROWN",
    "SWALLOWED_THROWN_STAR",
    "BITTEN_WARIO_START",
    "BITTEN_WARIO",
    "BITTEN_WARIO_END",
    "CLUNG_DIDDY",
    "CLUNG_DAMAGE_DIDDY",
    "CLUNG_THROWN_DIDDY",
    "CAPTURE_YOSHI",
    "YOSHI_EGG",
    "CAPTURE_PULLED_YOSHI",
    "CAPTURE_WAIT_YOSHI",
    "CAPTURE_DAMAGE_YOSHI",
    "AIR_LASSO",
    "AIR_LASSO_REACH",
    "AIR_LASSO_HANG",
    "AIR_LASSO_REWIND",
    "AIR_LASSO_FAILURE",
    "AIR_LASSO_LANDING",
    "CATCHED_REFLET",
    "CAPTURE_MASTERHAND",
    "KILLER",
    "ITEM_GRASS_PULL",
    "GIMMICK_EATEN",
    "GENESIS_SHOOT_START",
    "GENESIS_SHOOT",
    "GENESIS_SHOOT_END",
    "GENESIS_GET",
    "DEMO",
    "CAPTURE_ITEM",
    "CAPTURE_BEETLE",
    "CAPTURE_BLACKHOLE",
    "CAPTURE_BEITCRANE",
    "CAPTURE_KAWASAKI",
    "CAPTURE_DRIVER",
    "CAPTURE_MIMIKKYU",
    "CAPTURE_CLAPTRAP",
    "KASEY_WARP",
    "LADDER_CATCH",
    "LADDER_CATCH_BOTTOM",
    "LADDER",
    "LADDER_ATTACK",
    "LADDER_END",
    "CLIFF_ROBBED",
    "METAKNIGHT_FINAL_DAMAGE_FLY",
    "METAKNIGHT_FINAL_DAMAGE",
    "METAKNIGHT_FINAL_DAMAGE_FALL",
    "ITEM_ROCKETBELT_HOVER",
    "ITEM_ROCKETBELT_HOVER_KEEP",
    "ITEM_ROCKETBELT_HOP",
    "ITEM_SPECIALFLAG_HOIST",
    "KILLER_JUMP",
    "FINAL_VISUAL_ATTACK_OTHER",
    "CAPTAIN_FINAL_START",
    "CAPTAIN_FINAL_FURAFURA",
    "CAPTAIN_FINAL_CLASH",
    "CAPTAIN_FINAL_END",
    "CAPTURE_BOSSGALAGA",
    "ROCKMAN_FINAL_TARGET_SCENE01",
    "ROCKMAN_FINAL_TARGET_SCENE02",
    "ROCKMAN_FINAL_TARGET_END",
    "DUCKHUNT_FINAL_START",
    "DUCKHUNT_FINAL_FURAFURA",
    "DUCKHUNT_FINAL_END",
    "PACMAN_FINAL_EATEN",
    "SHULK_FINAL_START",
    "SHULK_FINAL_FURAFURA",
    "SHULK_FINAL_END",
    "MURABITO_FINAL_CAPTURE",
    "PALUTENA_FINAL_BLACKHOLE",
    "KIRBY_FINAL_CAPTURE",
    "LITTLEMAC_KO_CAPTURE",
    "CAPTURE_NABBIT",
    "CAPTURE_MASTERCORE",
    "LUIGI_FINAL_VACUUM",
    "LUIGI_FINAL_SHOOT",
    "IKE_FINAL_DAMAGE_FLY",
    "IKE_FINAL_DAMAGE",
    "IKE_FINAL_DAMAGE_FALL",
    "ZOROARK_FINAL_DAMAGE_FLY",
    "ZOROARK_FINAL_DAMAGE",
    "ZOROARK_FINAL_DAMAGE_FALL",
    "MIIFIGHTER_FINAL_DAMAGE_FLY",
    "MIIFIGHTER_FINAL_DAMAGE",
    "MIIFIGHTER_FINAL_DAMAGE_FALL",
    "GEKKOUGA_FINAL_DAMAGE_FLY",
    "GEKKOUGA_FINAL_DAMAGE",
    "GEKKOUGA_FINAL_DAMAGE_FALL",
    "REFLET_FINAL_DAMAGE_FLY",
    "REFLET_FINAL_DAMAGE",
    "REFLET_FINAL_DAMAGE_FALL",
    "MEWTWO_THROWN",
    "PSYCHOBREAK",
    "SAVING_DAMAGE",
    "SAVING_DAMAGE_FLY",
    "RYU_FINAL_DAMAGE",
    "RYU_FINAL_DAMAGE_FLY",
    "SAVING_DAMAGE_AIR",
    "CLOUD_FINAL_DAMAGE_FLY",
    "CLOUD_FINAL_DAMAGE",
    "CLOUD_FINAL_DAMAGE_FALL",
    "GIMMICK_ODIN_SLASHED",
    "BAYONETTA_FINAL_TARGET_START",
    "BAYONETTA_FINAL_TARGET_DAMAGE",
    "BAYONETTA_FINAL_TARGET_START2",
    "BAYONETTA_FINAL_TARGET_DAMAGE2",
    "BAYONETTA_FINAL_TARGET_END",
    "KAMUI_PIERCE",
    "KAMUI_FINAL_TARGET_START",
    "KAMUI_FINAL_TARGET_DAMAGE",
    "KAMUI_FINAL_TARGET_END",
    "DEDEDE_FINAL_TARGET_START",
    "DEDEDE_FINAL_TARGET_DAMAGE",
    "DEDEDE_FINAL_TARGET_END",
    "FOX_FINAL_TARGET_START",
    "FOX_FINAL_TARGET_DAMAGE",
    "FOX_FINAL_TARGET_END",
    "FALCO_FINAL_TARGET_START",
    "FALCO_FINAL_TARGET_DAMAGE",
    "FALCO_FINAL_TARGET_END",
    "KROOL_FINAL_TARGET_START",
    "KROOL_FINAL_TARGET_DAMAGE",
    "KROOL_FINAL_TARGET_END",
    "GAOGAEN_FINAL_TARGET_START",
    "GAOGAEN_FINAL_TARGET_DAMAGE",
    "GAOGAEN_FINAL_TARGET_END",
    "WARIO_FINAL_TARGET_START",
    "WARIO_FINAL_TARGET_DAMAGE",
    "WARIO_FINAL_TARGET_END",
    "RIDLEY_FINAL_TARGET_START",
    "RIDLEY_FINAL_TARGET_DAMAGE",
    "RIDLEY_FINAL_TARGET_END",
    "ITEM_STARRING",
    "ITEM_STARRING_SHOOT",
    "CATCHED_RIDLEY",
    "DRAGGED_RIDLEY",
    "STABBED_RIDLEY",
    "STABBED_DAMAGE",
    "FREE_MOVE",
    "SWING_GAOGAEN_CATCHED",
    "SWING_GAOGAEN_THROWN",
    "SWING_GAOGAEN_ATTACH_ROPE",
    "SWING_GAOGAEN_RETURN",
    "SWING_GAOGAEN_LARIAT",
    "SWING_GAOGAEN_SHOULDER",
    "SWING_GAOGAEN_FAILURE",
    "FINAL_JUMP_END",
    "SHEIK_FINAL_CAPTURE",
    "LITTLEMAC_FINAL_DAMAGE_FLY",
    "LITTLEMAC_FINAL_DAMAGE",
    "PIKACHU_FINAL_DAMAGE_FLY",
    "KOOPA_FINAL_DAMAGE_FLY",
    "MIIFIGHTER_COUNTER_THROWN",
    "MIIFIGHTER_SUPLEX_CATCHED",
    "MIIFIGHTER_SUPLEX_THROWN",
    "MIIFIGHTER_SUPLEX_AIR_CAPTURED",
    "MIIFIGHTER_SUPLEX_AIR_FALL",
    "MIIFIGHTER_SUPLEX_AIR_LANDING",
    "MIISWORDSMAN_COUNTER_DAMAGE",
    "CAPTURE_PULLED_FISHINGROD",
    "CAPTURE_PULLED_OCTOPUS",
    "CAPTURE_WAIT_OCTOPUS",
    "ROULETTE",
    "ROULETTE_FURAFURA",
    "SIMON_FINAL_TARGET_START",
    "SIMON_FINAL_TARGET_DAMAGE",
    "SIMON_FINAL_TARGET_END",
    "CHROM_FINAL_TARGET_DAMAGE",
    "YOSHI_FINAL_TARGET_START",
    "YOSHI_FINAL_TARGET_DAMAGE",
    "YOSHI_FINAL_TARGET_END",
    "METAMON_OUT",
    "BOSS_ENTRY",
    "BOSS_DEAD",
    "SUICIDE_BOMB",
    "STANDBY",
    "APPEAL",
    "SMASH_APPEAL",
    "ENTRY",
    "WIN",
    "LOSE",
    "SPECIAL_N",
    "SPECIAL_S",
    "SPECIAL_HI",
    "SPECIAL_LW",
    "FINAL",
    "FIGHTER_STATUS_KIND_MAX", // 0x1a5
    "UNK_1A6",
    "UNK_1A7"
};

void init_character_objects()
{
    std::vector<std::string> bayonetta_objs;
    bayonetta_objs.push_back("bayonetta");
    bayonetta_objs.push_back("bayonetta_bat");
    bayonetta_objs.push_back("bayonetta_gomorrah");
    bayonetta_objs.push_back("bayonetta_hair");
    bayonetta_objs.push_back("bayonetta_specialn_bullet");
    bayonetta_objs.push_back("bayonetta_wickedweavearm");
    bayonetta_objs.push_back("bayonetta_wickedweaveleg");
    character_objects["bayonetta"] = bayonetta_objs;

    std::vector<std::string> captain_objs;
    captain_objs.push_back("captain");
    captain_objs.push_back("captain_bluefalcon");
    captain_objs.push_back("captain_falconpunch");
    character_objects["captain"] = captain_objs;

    std::vector<std::string> chrom_objs;
    chrom_objs.push_back("chrom");
    chrom_objs.push_back("chrom_sword");
    character_objects["chrom"] = chrom_objs;

    std::vector<std::string> cloud_objs;
    cloud_objs.push_back("cloud");
    cloud_objs.push_back("cloud_wave");
    character_objects["cloud"] = cloud_objs;

    std::vector<std::string> daisy_objs;
    daisy_objs.push_back("daisy");
    daisy_objs.push_back("daisy_kassar");
    daisy_objs.push_back("daisy_kinopio");
    daisy_objs.push_back("daisy_kinopiospore");
    character_objects["daisy"] = daisy_objs;

    std::vector<std::string> dedede_objs;
    dedede_objs.push_back("dedede");
    dedede_objs.push_back("dedede_gordo");
    dedede_objs.push_back("dedede_jethammer");
    dedede_objs.push_back("dedede_mask");
    dedede_objs.push_back("dedede_missile");
    dedede_objs.push_back("dedede_newdededehammer");
    dedede_objs.push_back("dedede_shrine");
    dedede_objs.push_back("dedede_star");
    dedede_objs.push_back("dedede_star_missile");
    dedede_objs.push_back("dedede_waddledee");
    character_objects["dedede"] = dedede_objs;

    std::vector<std::string> diddy_objs;
    diddy_objs.push_back("diddy");
    diddy_objs.push_back("diddy_barreljet");
    diddy_objs.push_back("diddy_barreljets");
    diddy_objs.push_back("diddy_bunshin");
    diddy_objs.push_back("diddy_dkbarrel");
    diddy_objs.push_back("diddy_explosion");
    diddy_objs.push_back("diddy_gun");
    diddy_objs.push_back("diddy_lock_on_cursor");
    diddy_objs.push_back("diddy_peanuts");
    character_objects["diddy"] = diddy_objs;

    std::vector<std::string> donkey_objs;
    donkey_objs.push_back("donkey");
    donkey_objs.push_back("donkey_dkbarrel");
    character_objects["donkey"] = donkey_objs;

    std::vector<std::string> duckhunt_objs;
    duckhunt_objs.push_back("duckhunt");
    duckhunt_objs.push_back("duckhunt_can");
    duckhunt_objs.push_back("duckhunt_clay");
    duckhunt_objs.push_back("duckhunt_finalbird");
    duckhunt_objs.push_back("duckhunt_finalcan");
    duckhunt_objs.push_back("duckhunt_finaldog");
    duckhunt_objs.push_back("duckhunt_finalduck");
    duckhunt_objs.push_back("duckhunt_finalenemy");
    duckhunt_objs.push_back("duckhunt_finalgrass");
    duckhunt_objs.push_back("duckhunt_finalgunman");
    duckhunt_objs.push_back("duckhunt_grass");
    duckhunt_objs.push_back("duckhunt_gunman");
    duckhunt_objs.push_back("duckhunt_gunmanbullet");
    duckhunt_objs.push_back("duckhunt_kurofukuhat");
    duckhunt_objs.push_back("duckhunt_reticle");
    character_objects["duckhunt"] = duckhunt_objs;

    std::vector<std::string> falco_objs;
    falco_objs.push_back("falco");
    falco_objs.push_back("falco_arwing");
    falco_objs.push_back("falco_arwingshot");
    falco_objs.push_back("falco_blaster");
    falco_objs.push_back("falco_blaster_bullet");
    falco_objs.push_back("falco_illusion");
    falco_objs.push_back("falco_reticle");
    character_objects["falco"] = falco_objs;

    std::vector<std::string> fox_objs;
    fox_objs.push_back("fox");
    fox_objs.push_back("fox_arwing");
    fox_objs.push_back("fox_arwingshot");
    fox_objs.push_back("fox_blaster");
    fox_objs.push_back("fox_blaster_bullet");
    fox_objs.push_back("fox_illusion");
    fox_objs.push_back("fox_reticle");
    character_objects["fox"] = fox_objs;

    std::vector<std::string> fushigisou_objs;
    fushigisou_objs.push_back("fushigisou");
    character_objects["fushigisou"] = fushigisou_objs;

    std::vector<std::string> gamewatch_objs;
    gamewatch_objs.push_back("gamewatch");
    gamewatch_objs.push_back("gamewatch_bomb");
    gamewatch_objs.push_back("gamewatch_breath");
    gamewatch_objs.push_back("gamewatch_entry");
    gamewatch_objs.push_back("gamewatch_food");
    gamewatch_objs.push_back("gamewatch_normal_weapon");
    gamewatch_objs.push_back("gamewatch_octopus");
    gamewatch_objs.push_back("gamewatch_oil");
    gamewatch_objs.push_back("gamewatch_panel");
    gamewatch_objs.push_back("gamewatch_parachute");
    gamewatch_objs.push_back("gamewatch_rescue");
    character_objects["gamewatch"] = gamewatch_objs;

    std::vector<std::string> ganon_objs;
    ganon_objs.push_back("ganon");
    ganon_objs.push_back("ganon_beast");
    ganon_objs.push_back("ganon_ganond");
    ganon_objs.push_back("ganon_sword");
    character_objects["ganon"] = ganon_objs;

    std::vector<std::string> gaogaen_objs;
    gaogaen_objs.push_back("gaogaen");
    gaogaen_objs.push_back("gaogaen_championbelt");
    gaogaen_objs.push_back("gaogaen_monsterball");
    gaogaen_objs.push_back("gaogaen_rope");
    gaogaen_objs.push_back("gaogaen_rope2");
    character_objects["gaogaen"] = gaogaen_objs;

    std::vector<std::string> gekkouga_objs;
    gekkouga_objs.push_back("gekkouga");
    gekkouga_objs.push_back("gekkouga_bunshin");
    gekkouga_objs.push_back("gekkouga_gekkougas");
    gekkouga_objs.push_back("gekkouga_monsterball");
    gekkouga_objs.push_back("gekkouga_moon");
    gekkouga_objs.push_back("gekkouga_shuriken");
    gekkouga_objs.push_back("gekkouga_tatami");
    gekkouga_objs.push_back("gekkouga_water");
    character_objects["gekkouga"] = gekkouga_objs;

    std::vector<std::string> ice_climber_objs;
    ice_climber_objs.push_back("ice_climber");
    character_objects["ice_climber"] = ice_climber_objs;

    std::vector<std::string> ike_objs;
    ike_objs.push_back("ike");
    ike_objs.push_back("ike_sword");
    character_objects["ike"] = ike_objs;

    std::vector<std::string> inkling_objs;
    inkling_objs.push_back("inkling");
    inkling_objs.push_back("inkling_blaster");
    inkling_objs.push_back("inkling_brush");
    inkling_objs.push_back("inkling_copy_inklinggun");
    inkling_objs.push_back("inkling_copy_inklingtank");
    inkling_objs.push_back("inkling_inkbullet");
    inkling_objs.push_back("inkling_megaphonelaser");
    inkling_objs.push_back("inkling_roller");
    inkling_objs.push_back("inkling_rollerink");
    inkling_objs.push_back("inkling_slosher");
    inkling_objs.push_back("inkling_splash");
    inkling_objs.push_back("inkling_splashbomb");
    inkling_objs.push_back("inkling_squid");
    character_objects["inkling"] = inkling_objs;

    std::vector<std::string> kamui_objs;
    kamui_objs.push_back("kamui");
    kamui_objs.push_back("kamui_dragonhand");
    kamui_objs.push_back("kamui_ryusensya");
    kamui_objs.push_back("kamui_spearhand");
    kamui_objs.push_back("kamui_waterdragon");
    kamui_objs.push_back("kamui_waterstream");
    character_objects["kamui"] = kamui_objs;

    std::vector<std::string> ken_objs;
    ken_objs.push_back("ken");
    ken_objs.push_back("ken_hadoken");
    ken_objs.push_back("ken_shinkuhadoken");
    ken_objs.push_back("ken_shinryuken");
    character_objects["ken"] = ken_objs;

    std::vector<std::string> kirby_objs;
    kirby_objs.push_back("kirby");
    kirby_objs.push_back("kirby_finalcutter");
    kirby_objs.push_back("kirby_finalcuttershot");
    kirby_objs.push_back("kirby_hammer");
    kirby_objs.push_back("kirby_hat");
    kirby_objs.push_back("kirby_miipartshead");
    kirby_objs.push_back("kirby_reserve");
    kirby_objs.push_back("kirby_rosettaticomissile");
    kirby_objs.push_back("kirby_simple");
    kirby_objs.push_back("kirby_simple2l");
    kirby_objs.push_back("kirby_simple2r");
    kirby_objs.push_back("kirby_starmissile");
    kirby_objs.push_back("kirby_stone");
    kirby_objs.push_back("kirby_ultrasword");
    kirby_objs.push_back("kirby_ultraswordhat");
    kirby_objs.push_back("kirby_warpstar");
    kirby_objs.push_back("kirby_windummy");
    character_objects["kirby"] = kirby_objs;

    std::vector<std::string> koopa_objs;
    koopa_objs.push_back("koopa");
    koopa_objs.push_back("koopa_breath");
    koopa_objs.push_back("koopag");
    koopa_objs.push_back("koopag_breath");
    koopa_objs.push_back("koopajr");
    koopa_objs.push_back("koopajr_batten");
    koopa_objs.push_back("koopajr_cannonball");
    koopa_objs.push_back("koopajr_hammer");
    koopa_objs.push_back("koopajr_kart");
    koopa_objs.push_back("koopajr_magichand");
    koopa_objs.push_back("koopajr_picopicohammer");
    koopa_objs.push_back("koopajr_remainclown");
    koopa_objs.push_back("koopajr_shadowmario");
    koopa_objs.push_back("koopa_koopag");
    character_objects["koopa"] = koopa_objs;

    std::vector<std::string> koopag_objs;
    koopag_objs.push_back("koopag");
    koopag_objs.push_back("koopag_breath");
    character_objects["koopag"] = koopag_objs;

    std::vector<std::string> koopajr_objs;
    koopajr_objs.push_back("koopajr");
    koopajr_objs.push_back("koopajr_batten");
    koopajr_objs.push_back("koopajr_cannonball");
    koopajr_objs.push_back("koopajr_hammer");
    koopajr_objs.push_back("koopajr_kart");
    koopajr_objs.push_back("koopajr_magichand");
    koopajr_objs.push_back("koopajr_picopicohammer");
    koopajr_objs.push_back("koopajr_remainclown");
    koopajr_objs.push_back("koopajr_shadowmario");
    character_objects["koopajr"] = koopajr_objs;

    std::vector<std::string> krool_objs;
    krool_objs.push_back("krool");
    krool_objs.push_back("krool_backpack");
    krool_objs.push_back("krool_blunderbuss");
    krool_objs.push_back("krool_crown");
    krool_objs.push_back("krool_ironball");
    krool_objs.push_back("krool_piratehat");
    krool_objs.push_back("krool_spitball");
    character_objects["krool"] = krool_objs;

    std::vector<std::string> link_objs;
    link_objs.push_back("link");
    link_objs.push_back("link_ancient_bow");
    link_objs.push_back("link_ancient_bowarrow");
    link_objs.push_back("link_boomerang");
    link_objs.push_back("link_bow");
    link_objs.push_back("link_bowarrow");
    link_objs.push_back("link_navy");
    link_objs.push_back("link_parasail");
    link_objs.push_back("link_sword_beam");
    character_objects["link"] = link_objs;

    std::vector<std::string> littlemac_objs;
    littlemac_objs.push_back("littlemac");
    littlemac_objs.push_back("littlemac_championbelt");
    littlemac_objs.push_back("littlemac_doclouis");
    littlemac_objs.push_back("littlemac_littlemacg");
    littlemac_objs.push_back("littlemac_sweatlittlemac");
    littlemac_objs.push_back("littlemac_throwsweat");
    character_objects["littlemac"] = littlemac_objs;

    std::vector<std::string> lizardon_objs;
    lizardon_objs.push_back("lizardon");
    character_objects["lizardon"] = lizardon_objs;

    std::vector<std::string> lucario_objs;
    lucario_objs.push_back("lucario");
    lucario_objs.push_back("lucario_auraball");
    lucario_objs.push_back("lucario_lucariom");
    lucario_objs.push_back("lucario_qigong");
    character_objects["lucario"] = lucario_objs;

    std::vector<std::string> lucas_objs;
    lucas_objs.push_back("lucas");
    lucas_objs.push_back("lucas_bonnie");
    lucas_objs.push_back("lucas_doseitable");
    lucas_objs.push_back("lucas_himohebi");
    lucas_objs.push_back("lucas_himohebi2");
    lucas_objs.push_back("lucas_kumatora");
    lucas_objs.push_back("lucas_needle");
    lucas_objs.push_back("lucas_pk_fire");
    lucas_objs.push_back("lucas_pk_freeze");
    lucas_objs.push_back("lucas_pk_starstorm");
    lucas_objs.push_back("lucas_pk_thunder");
    character_objects["lucas"] = lucas_objs;

    std::vector<std::string> lucina_objs;
    lucina_objs.push_back("lucina");
    lucina_objs.push_back("lucina_mask");
    character_objects["lucina"] = lucina_objs;

    std::vector<std::string> luigi_objs;
    luigi_objs.push_back("luigi");
    luigi_objs.push_back("luigi_dokan");
    luigi_objs.push_back("luigi_fireball");
    luigi_objs.push_back("luigi_obakyumu");
    luigi_objs.push_back("luigi_plunger");
    character_objects["luigi"] = luigi_objs;

    std::vector<std::string> mario_objs;
    mario_objs.push_back("mario");
    mario_objs.push_back("mario_cappy");
    mario_objs.push_back("mariod");
    mario_objs.push_back("mariod_capsuleblock");
    mario_objs.push_back("mariod_drcapsule");
    mario_objs.push_back("mariod_drmantle");
    mario_objs.push_back("mariod_huge_capsule");
    mario_objs.push_back("mario_dokan");
    mario_objs.push_back("mariod_stethoscope");
    mario_objs.push_back("mario_fireball");
    mario_objs.push_back("mario_huge_flame");
    mario_objs.push_back("mario_mantle");
    mario_objs.push_back("mario_pump");
    mario_objs.push_back("mario_pump_water");
    character_objects["mario"] = mario_objs;

    std::vector<std::string> mariod_objs;
    mariod_objs.push_back("mariod");
    mariod_objs.push_back("mariod_capsuleblock");
    mariod_objs.push_back("mariod_drcapsule");
    mariod_objs.push_back("mariod_drmantle");
    mariod_objs.push_back("mariod_huge_capsule");
    mariod_objs.push_back("mariod_stethoscope");
    character_objects["mariod"] = mariod_objs;

    std::vector<std::string> marth_objs;
    marth_objs.push_back("marth");
    character_objects["marth"] = marth_objs;

    std::vector<std::string> metaknight_objs;
    metaknight_objs.push_back("metaknight");
    metaknight_objs.push_back("metaknight_bunshin");
    metaknight_objs.push_back("metaknight_fourwings");
    metaknight_objs.push_back("metaknight_mantle");
    character_objects["metaknight"] = metaknight_objs;

    std::vector<std::string> mewtwo_objs;
    mewtwo_objs.push_back("mewtwo");
    mewtwo_objs.push_back("mewtwo_bindball");
    mewtwo_objs.push_back("mewtwo_escapeairdummy");
    mewtwo_objs.push_back("mewtwo_mewtwom");
    mewtwo_objs.push_back("mewtwo_psychobreak");
    mewtwo_objs.push_back("mewtwo_search");
    mewtwo_objs.push_back("mewtwo_shadowball");
    character_objects["mewtwo"] = mewtwo_objs;

    std::vector<std::string> miienemyf_objs;
    miienemyf_objs.push_back("miienemyf");
    character_objects["miienemyf"] = miienemyf_objs;

    std::vector<std::string> miienemyg_objs;
    miienemyg_objs.push_back("miienemyg");
    miienemyg_objs.push_back("miienemyg_attackairf_bullet");
    miienemyg_objs.push_back("miienemyg_rapidshot_bullet");
    character_objects["miienemyg"] = miienemyg_objs;

    std::vector<std::string> miienemys_objs;
    miienemys_objs.push_back("miienemys");
    character_objects["miienemys"] = miienemys_objs;

    std::vector<std::string> miifighter_objs;
    miifighter_objs.push_back("miifighter");
    miifighter_objs.push_back("miifighter_hat");
    miifighter_objs.push_back("miifighter_ironball");
    character_objects["miifighter"] = miifighter_objs;

    std::vector<std::string> miigunner_objs;
    miigunner_objs.push_back("miigunner");
    miigunner_objs.push_back("miigunner_attackairf_bullet");
    miigunner_objs.push_back("miigunner_bottomshoot");
    miigunner_objs.push_back("miigunner_flamepillar");
    miigunner_objs.push_back("miigunner_fullthrottle");
    miigunner_objs.push_back("miigunner_grenadelauncher");
    miigunner_objs.push_back("miigunner_groundbomb");
    miigunner_objs.push_back("miigunner_gunnercharge");
    miigunner_objs.push_back("miigunner_hat");
    miigunner_objs.push_back("miigunner_laser");
    miigunner_objs.push_back("miigunner_miimissile");
    miigunner_objs.push_back("miigunner_rapidshot_bullet");
    miigunner_objs.push_back("miigunner_stealthbomb");
    miigunner_objs.push_back("miigunner_stealthbomb_s");
    miigunner_objs.push_back("miigunner_supermissile");
    character_objects["miigunner"] = miigunner_objs;

    std::vector<std::string> miiswordsman_objs;
    miiswordsman_objs.push_back("miiswordsman");
    miiswordsman_objs.push_back("miiswordsman_chakram");
    miiswordsman_objs.push_back("miiswordsman_hat");
    miiswordsman_objs.push_back("miiswordsman_lightshuriken");
    miiswordsman_objs.push_back("miiswordsman_tornadoshot");
    miiswordsman_objs.push_back("miiswordsman_wave");
    character_objects["miiswordsman"] = miiswordsman_objs;

    std::vector<std::string> murabito_objs;
    murabito_objs.push_back("murabito");
    murabito_objs.push_back("murabito_balloon");
    murabito_objs.push_back("murabito_beetle");
    murabito_objs.push_back("murabito_bowling_ball");
    murabito_objs.push_back("murabito_bullet");
    murabito_objs.push_back("murabito_butterflynet");
    murabito_objs.push_back("murabito_clayrocket");
    murabito_objs.push_back("murabito_firework");
    murabito_objs.push_back("murabito_flowerpot");
    murabito_objs.push_back("murabito_furniture");
    murabito_objs.push_back("murabito_helmet");
    murabito_objs.push_back("murabito_house");
    murabito_objs.push_back("murabito_moneybag");
    murabito_objs.push_back("murabito_seed");
    murabito_objs.push_back("murabito_slingshot");
    murabito_objs.push_back("murabito_sprinkling_water");
    murabito_objs.push_back("murabito_sprout");
    murabito_objs.push_back("murabito_stump");
    murabito_objs.push_back("murabito_timmy");
    murabito_objs.push_back("murabito_tommy");
    murabito_objs.push_back("murabito_tomnook");
    murabito_objs.push_back("murabito_tree");
    murabito_objs.push_back("murabito_umbrella");
    murabito_objs.push_back("murabito_weeds");
    character_objects["murabito"] = murabito_objs;

    std::vector<std::string> nana_objs;
    nana_objs.push_back("nana");
    character_objects["nana"] = nana_objs;

    std::vector<std::string> ness_objs;
    ness_objs.push_back("ness");
    ness_objs.push_back("ness_paula");
    ness_objs.push_back("ness_pk_fire");
    ness_objs.push_back("ness_pk_flash");
    ness_objs.push_back("ness_pk_starstorm");
    ness_objs.push_back("ness_pk_thunder");
    ness_objs.push_back("ness_poo");
    ness_objs.push_back("ness_yoyo");
    ness_objs.push_back("ness_yoyo_head");
    character_objects["ness"] = ness_objs;

    std::vector<std::string> none_objs;
    none_objs.push_back("none");
    character_objects["none"] = none_objs;

    std::vector<std::string> pacman_objs;
    pacman_objs.push_back("pacman");
    pacman_objs.push_back("pacman_artisticpoint");
    pacman_objs.push_back("pacman_bigpacman");
    pacman_objs.push_back("pacman_esa");
    pacman_objs.push_back("pacman_fairy");
    pacman_objs.push_back("pacman_firehydrant");
    pacman_objs.push_back("pacman_firehydrant_water");
    pacman_objs.push_back("pacman_trampoline");
    character_objects["pacman"] = pacman_objs;

    std::vector<std::string> palutena_objs;
    palutena_objs.push_back("palutena");
    palutena_objs.push_back("palutena_autoaimbullet");
    palutena_objs.push_back("palutena_autoreticle");
    palutena_objs.push_back("palutena_beam");
    palutena_objs.push_back("palutena_blackhole");
    palutena_objs.push_back("palutena_explosiveflame");
    palutena_objs.push_back("palutena_explosiveflame_reserve");
    palutena_objs.push_back("palutena_gate");
    palutena_objs.push_back("palutena_godwing");
    palutena_objs.push_back("palutena_reflectionboard");
    character_objects["palutena"] = palutena_objs;

    std::vector<std::string> peach_objs;
    peach_objs.push_back("peach");
    peach_objs.push_back("peach_kassar");
    peach_objs.push_back("peach_kinopio");
    peach_objs.push_back("peach_kinopiospore");
    character_objects["peach"] = peach_objs;

    std::vector<std::string> pfushigisou_objs;
    pfushigisou_objs.push_back("pfushigisou");
    pfushigisou_objs.push_back("pfushigisou_leafcutter");
    pfushigisou_objs.push_back("pfushigisou_seed");
    pfushigisou_objs.push_back("pfushigisou_vine");
    character_objects["pfushigisou"] = pfushigisou_objs;

    std::vector<std::string> pichu_objs;
    pichu_objs.push_back("pichu");
    pichu_objs.push_back("pichu_cloud");
    pichu_objs.push_back("pichu_dengeki");
    pichu_objs.push_back("pichu_dengekidama");
    pichu_objs.push_back("pichu_kaminari");
    pichu_objs.push_back("pichu_monsterball");
    pichu_objs.push_back("pichu_specialupdummy");
    pichu_objs.push_back("pichu_vortex");
    character_objects["pichu"] = pichu_objs;

    std::vector<std::string> pikachu_objs;
    pikachu_objs.push_back("pikachu");
    pikachu_objs.push_back("pikachu_cloud");
    pikachu_objs.push_back("pikachu_dengeki");
    pikachu_objs.push_back("pikachu_dengekidama");
    pikachu_objs.push_back("pikachu_kaminari");
    pikachu_objs.push_back("pikachu_monsterball");
    pikachu_objs.push_back("pikachu_specialupdummy");
    pikachu_objs.push_back("pikachu_vortex");
    character_objects["pikachu"] = pikachu_objs;

    std::vector<std::string> pikmin_objs;
    pikmin_objs.push_back("pikmin");
    pikmin_objs.push_back("pikmin_dolfin");
    pikmin_objs.push_back("pikmin_pikmin");
    pikmin_objs.push_back("pikmin_win1");
    pikmin_objs.push_back("pikmin_win2");
    pikmin_objs.push_back("pikmin_win3");
    character_objects["pikmin"] = pikmin_objs;

    std::vector<std::string> pit_objs;
    pit_objs.push_back("pit");
    pit_objs.push_back("pitb");
    pit_objs.push_back("pitb_bow");
    pit_objs.push_back("pitb_bowarrow");
    pit_objs.push_back("pit_bow");
    pit_objs.push_back("pit_bowarrow");
    pit_objs.push_back("pit_chariot");
    pit_objs.push_back("pit_chariotsight");
    pit_objs.push_back("pit_horse");
    character_objects["pit"] = pit_objs;

    std::vector<std::string> pitb_objs;
    pitb_objs.push_back("pitb");
    pitb_objs.push_back("pitb_bow");
    pitb_objs.push_back("pitb_bowarrow");
    character_objects["pitb"] = pitb_objs;

    std::vector<std::string> plizardon_objs;
    plizardon_objs.push_back("plizardon");
    plizardon_objs.push_back("plizardon_breath");
    plizardon_objs.push_back("plizardon_daimonji");
    plizardon_objs.push_back("plizardon_explosion");
    character_objects["plizardon"] = plizardon_objs;

    std::vector<std::string> popo_objs;
    popo_objs.push_back("popo");
    popo_objs.push_back("popo_blizzard");
    popo_objs.push_back("popo_condor");
    popo_objs.push_back("popo_iceberg");
    popo_objs.push_back("popo_iceberg_hit");
    popo_objs.push_back("popo_iceberg_wind");
    popo_objs.push_back("popo_iceshot");
    popo_objs.push_back("popo_rubber");
    popo_objs.push_back("popo_whitebear");
    character_objects["popo"] = popo_objs;

    std::vector<std::string> ptrainer_objs;
    ptrainer_objs.push_back("ptrainer");
    ptrainer_objs.push_back("ptrainer_mball");
    ptrainer_objs.push_back("ptrainer_pfushigisou");
    ptrainer_objs.push_back("ptrainer_plizardon");
    ptrainer_objs.push_back("ptrainer_ptrainer");
    ptrainer_objs.push_back("ptrainer_pzenigame");
    character_objects["ptrainer"] = ptrainer_objs;

    std::vector<std::string> purin_objs;
    purin_objs.push_back("purin");
    purin_objs.push_back("purin_cap");
    purin_objs.push_back("purin_monsterball");
    character_objects["purin"] = purin_objs;

    std::vector<std::string> pzenigame_objs;
    pzenigame_objs.push_back("pzenigame");
    pzenigame_objs.push_back("pzenigame_water");
    character_objects["pzenigame"] = pzenigame_objs;

    std::vector<std::string> random_objs;
    random_objs.push_back("random");
    character_objects["random"] = random_objs;

    std::vector<std::string> reflet_objs;
    reflet_objs.push_back("reflet");
    reflet_objs.push_back("reflet_book");
    reflet_objs.push_back("reflet_chrom");
    reflet_objs.push_back("reflet_elwind");
    reflet_objs.push_back("reflet_gigafire");
    reflet_objs.push_back("reflet_thunder");
    reflet_objs.push_back("reflet_window");
    character_objects["reflet"] = reflet_objs;

    std::vector<std::string> richter_objs;
    richter_objs.push_back("richter");
    richter_objs.push_back("richter_axe");
    richter_objs.push_back("richter_coffin");
    richter_objs.push_back("richter_cross");
    richter_objs.push_back("richter_crystal");
    richter_objs.push_back("richter_stake");
    richter_objs.push_back("richter_whip");
    richter_objs.push_back("richter_whip2");
    richter_objs.push_back("richter_whiphand");
    richter_objs.push_back("richter_whipwire");
    character_objects["richter"] = richter_objs;

    std::vector<std::string> ridley_objs;
    ridley_objs.push_back("ridley");
    ridley_objs.push_back("ridley_breath");
    ridley_objs.push_back("ridley_gunship");
    character_objects["ridley"] = ridley_objs;

    std::vector<std::string> robot_objs;
    robot_objs.push_back("robot");
    robot_objs.push_back("robot_beam");
    robot_objs.push_back("robot_final_beam");
    robot_objs.push_back("robot_gyro");
    robot_objs.push_back("robot_gyro_holder");
    robot_objs.push_back("robot_hominglaser");
    robot_objs.push_back("robot_homingtarget");
    robot_objs.push_back("robot_hugebeam");
    robot_objs.push_back("robot_mainlaser");
    robot_objs.push_back("robot_narrowbeam");
    robot_objs.push_back("robot_widebeam");
    character_objects["robot"] = robot_objs;

    std::vector<std::string> rockman_objs;
    rockman_objs.push_back("rockman");
    rockman_objs.push_back("rockman_airshooter");
    rockman_objs.push_back("rockman_blackhole");
    rockman_objs.push_back("rockman_bruce");
    rockman_objs.push_back("rockman_chargeshot");
    rockman_objs.push_back("rockman_crashbomb");
    rockman_objs.push_back("rockman_forte");
    rockman_objs.push_back("rockman_hardknuckle");
    rockman_objs.push_back("rockman_leafshield");
    rockman_objs.push_back("rockman_leftarm");
    rockman_objs.push_back("rockman_rightarm");
    rockman_objs.push_back("rockman_rockbuster");
    rockman_objs.push_back("rockman_rockmandash");
    rockman_objs.push_back("rockman_rockmanexe");
    rockman_objs.push_back("rockman_rockmanx");
    rockman_objs.push_back("rockman_rushcoil");
    rockman_objs.push_back("rockman_shootingstarrockman");
    character_objects["rockman"] = rockman_objs;

    std::vector<std::string> rosetta_objs;
    rosetta_objs.push_back("rosetta");
    rosetta_objs.push_back("rosetta_meteor");
    rosetta_objs.push_back("rosetta_pointer");
    rosetta_objs.push_back("rosetta_powerstar");
    rosetta_objs.push_back("rosetta_ring");
    rosetta_objs.push_back("rosetta_starpiece");
    rosetta_objs.push_back("rosetta_tico");
    character_objects["rosetta"] = rosetta_objs;

    std::vector<std::string> roy_objs;
    roy_objs.push_back("roy");
    roy_objs.push_back("roy_sword");
    character_objects["roy"] = roy_objs;

    std::vector<std::string> ryu_objs;
    ryu_objs.push_back("ryu");
    ryu_objs.push_back("ryu_hadoken");
    ryu_objs.push_back("ryu_sack");
    ryu_objs.push_back("ryu_shinkuhadoken");
    character_objects["ryu"] = ryu_objs;

    std::vector<std::string> samus_objs;
    samus_objs.push_back("samus");
    samus_objs.push_back("samus_bomb");
    samus_objs.push_back("samus_cshot");
    samus_objs.push_back("samusd");
    samus_objs.push_back("samusd_bomb");
    samus_objs.push_back("samusd_bunshin");
    samus_objs.push_back("samusd_cshot");
    samus_objs.push_back("samusd_gbeam");
    samus_objs.push_back("samusd_gun");
    samus_objs.push_back("samusd_laser");
    samus_objs.push_back("samusd_laser2");
    samus_objs.push_back("samusd_missile");
    samus_objs.push_back("samusd_supermissile");
    samus_objs.push_back("samusd_transportation");
    samus_objs.push_back("samus_gbeam");
    samus_objs.push_back("samus_gun");
    samus_objs.push_back("samus_laser");
    samus_objs.push_back("samus_laser2");
    samus_objs.push_back("samus_missile");
    samus_objs.push_back("samus_supermissile");
    samus_objs.push_back("samus_transportation");
    character_objects["samus"] = samus_objs;

    std::vector<std::string> samusd_objs;
    samusd_objs.push_back("samusd");
    samusd_objs.push_back("samusd_bomb");
    samusd_objs.push_back("samusd_bunshin");
    samusd_objs.push_back("samusd_cshot");
    samusd_objs.push_back("samusd_gbeam");
    samusd_objs.push_back("samusd_gun");
    samusd_objs.push_back("samusd_laser");
    samusd_objs.push_back("samusd_laser2");
    samusd_objs.push_back("samusd_missile");
    samusd_objs.push_back("samusd_supermissile");
    samusd_objs.push_back("samusd_transportation");
    character_objects["samusd"] = samusd_objs;

    std::vector<std::string> sheik_objs;
    sheik_objs.push_back("sheik");
    sheik_objs.push_back("sheik_fusin");
    sheik_objs.push_back("sheik_knife");
    sheik_objs.push_back("sheik_needle");
    sheik_objs.push_back("sheik_needlehave");
    character_objects["sheik"] = sheik_objs;

    std::vector<std::string> shizue_objs;
    shizue_objs.push_back("shizue");
    shizue_objs.push_back("shizue_balloon");
    shizue_objs.push_back("shizue_broom");
    shizue_objs.push_back("shizue_bucket");
    shizue_objs.push_back("shizue_bullet");
    shizue_objs.push_back("shizue_butterflynet");
    shizue_objs.push_back("shizue_clayrocket");
    shizue_objs.push_back("shizue_cracker");
    shizue_objs.push_back("shizue_fishingline");
    shizue_objs.push_back("shizue_fishingrod");
    shizue_objs.push_back("shizue_furniture");
    shizue_objs.push_back("shizue_moneybag");
    shizue_objs.push_back("shizue_office");
    shizue_objs.push_back("shizue_picopicohammer");
    shizue_objs.push_back("shizue_pompon");
    shizue_objs.push_back("shizue_pot");
    shizue_objs.push_back("shizue_slingshot");
    shizue_objs.push_back("shizue_swing");
    shizue_objs.push_back("shizue_timmy");
    shizue_objs.push_back("shizue_tommy");
    shizue_objs.push_back("shizue_tomnook");
    shizue_objs.push_back("shizue_trafficsign");
    shizue_objs.push_back("shizue_umbrella");
    shizue_objs.push_back("shizue_weeds");
    character_objects["shizue"] = shizue_objs;

    std::vector<std::string> shulk_objs;
    shulk_objs.push_back("shulk");
    shulk_objs.push_back("shulk_dunban");
    shulk_objs.push_back("shulk_fiora");
    shulk_objs.push_back("shulk_riki");
    character_objects["shulk"] = shulk_objs;

    std::vector<std::string> simon_objs;
    simon_objs.push_back("simon");
    simon_objs.push_back("simon_axe");
    simon_objs.push_back("simon_coffin");
    simon_objs.push_back("simon_cross");
    simon_objs.push_back("simon_crystal");
    simon_objs.push_back("simon_stake");
    simon_objs.push_back("simon_whip");
    simon_objs.push_back("simon_whip2");
    simon_objs.push_back("simon_whiphand");
    simon_objs.push_back("simon_whipwire");
    character_objects["simon"] = simon_objs;

    std::vector<std::string> snake_objs;
    snake_objs.push_back("snake");
    snake_objs.push_back("snake_c4");
    snake_objs.push_back("snake_c4_switch");
    snake_objs.push_back("snake_cypher");
    snake_objs.push_back("snake_flare_grenades");
    snake_objs.push_back("snake_grenade");
    snake_objs.push_back("snake_lock_on_cursor");
    snake_objs.push_back("snake_lock_on_cursor_ready");
    snake_objs.push_back("snake_missile");
    snake_objs.push_back("snake_nikita");
    snake_objs.push_back("snake_nikita_missile");
    snake_objs.push_back("snake_reticle");
    snake_objs.push_back("snake_reticle_cursor");
    snake_objs.push_back("snake_rpg7");
    snake_objs.push_back("snake_trenchmortar");
    snake_objs.push_back("snake_trenchmortar_bullet");
    character_objects["snake"] = snake_objs;

    std::vector<std::string> sonic_objs;
    sonic_objs.push_back("sonic");
    sonic_objs.push_back("sonic_chaosemerald");
    sonic_objs.push_back("sonic_gimmickjump");
    sonic_objs.push_back("sonic_homingtarget");
    sonic_objs.push_back("sonic_supersonic");
    character_objects["sonic"] = sonic_objs;

    std::vector<std::string> szerosuit_objs;
    szerosuit_objs.push_back("szerosuit");
    szerosuit_objs.push_back("szerosuit_gunship");
    szerosuit_objs.push_back("szerosuit_laser");
    szerosuit_objs.push_back("szerosuit_paralyzer");
    szerosuit_objs.push_back("szerosuit_paralyzer_bullet");
    szerosuit_objs.push_back("szerosuit_reticle");
    szerosuit_objs.push_back("szerosuit_samusp");
    szerosuit_objs.push_back("szerosuit_whip");
    szerosuit_objs.push_back("szerosuit_whip2");
    character_objects["szerosuit"] = szerosuit_objs;

    std::vector<std::string> toonlink_objs;
    toonlink_objs.push_back("toonlink");
    toonlink_objs.push_back("toonlink_boomerang");
    toonlink_objs.push_back("toonlink_bow");
    toonlink_objs.push_back("toonlink_bowarrow");
    toonlink_objs.push_back("toonlink_fairy");
    toonlink_objs.push_back("toonlink_hookshot");
    toonlink_objs.push_back("toonlink_hookshot_hand");
    toonlink_objs.push_back("toonlink_pig");
    toonlink_objs.push_back("toonlink_takt");
    character_objects["toonlink"] = toonlink_objs;

    std::vector<std::string> wario_objs;
    wario_objs.push_back("wario");
    wario_objs.push_back("wario_garlic");
    wario_objs.push_back("wario_wariobike");
    wario_objs.push_back("wario_warioman");
    character_objects["wario"] = wario_objs;

    std::vector<std::string> wiifit_objs;
    wiifit_objs.push_back("wiifit");
    wiifit_objs.push_back("wiifit_balanceboard");
    wiifit_objs.push_back("wiifit_hulahoop");
    wiifit_objs.push_back("wiifit_silhouette");
    wiifit_objs.push_back("wiifit_silhouettel");
    wiifit_objs.push_back("wiifit_sunbullet");
    wiifit_objs.push_back("wiifit_towel");
    wiifit_objs.push_back("wiifit_wiibo");
    character_objects["wiifit"] = wiifit_objs;

    std::vector<std::string> wolf_objs;
    wolf_objs.push_back("wolf");
    wolf_objs.push_back("wolf_blaster");
    wolf_objs.push_back("wolf_blaster_bullet");
    wolf_objs.push_back("wolf_illusion");
    wolf_objs.push_back("wolf_reticle");
    wolf_objs.push_back("wolf_wolfen");
    character_objects["wolf"] = wolf_objs;

    std::vector<std::string> yoshi_objs;
    yoshi_objs.push_back("yoshi");
    yoshi_objs.push_back("yoshi_star");
    yoshi_objs.push_back("yoshi_tamago");
    yoshi_objs.push_back("yoshi_yoshibg01");
    yoshi_objs.push_back("yoshi_yoshimob");
    character_objects["yoshi"] = yoshi_objs;

    std::vector<std::string> younglink_objs;
    younglink_objs.push_back("younglink");
    younglink_objs.push_back("younglink_boomerang");
    younglink_objs.push_back("younglink_bow");
    younglink_objs.push_back("younglink_bowarrow");
    younglink_objs.push_back("younglink_hookshot");
    younglink_objs.push_back("younglink_hookshot_hand");
    younglink_objs.push_back("younglink_milk");
    younglink_objs.push_back("younglink_navy");
    character_objects["younglink"] = younglink_objs;

    std::vector<std::string> zelda_objs;
    zelda_objs.push_back("zelda");
    zelda_objs.push_back("zelda_dein");
    zelda_objs.push_back("zelda_dein_s");
    zelda_objs.push_back("zelda_phantom");
    zelda_objs.push_back("zelda_triforce");
    character_objects["zelda"] = zelda_objs;

    std::vector<std::string> zenigame_objs;
    zenigame_objs.push_back("zenigame");
    character_objects["zenigame"] = zenigame_objs;
    
    std::vector<std::string> common_objs;
    common_objs.push_back("common");
    common_objs.push_back("fighter_common");
    common_objs.push_back("base");
    character_objects["common"] = common_objs;
}

struct nso_header
{
    uint32_t start;
    uint32_t mod;
};

struct mod0_header
{
    uint32_t magic;
    int32_t dynamic;
    int32_t bss_start;
    int32_t bss_end;
    int32_t unwind_start;
    int32_t unwind_end;
};

void nro_assignsyms(void* base)
{
    const Elf64_Dyn* dyn = NULL;
    const Elf64_Sym* symtab = NULL;
    const char* strtab = NULL;
    uint64_t numsyms = 0;
    
    if (syms_scanned) return;
    
    struct nso_header* header = (struct nso_header*)base;
    struct mod0_header* modheader = (struct mod0_header*)(base + header->mod);
    dyn = (const Elf64_Dyn*)(base + header->mod + modheader->dynamic);
    
    //parse_eh(base, header->mod + modheader->unwind_start);
    
    for (; dyn->d_tag != DT_NULL; dyn++)
    {
        switch (dyn->d_tag)
        {
            case DT_SYMTAB:
                symtab = (const Elf64_Sym*)(base + dyn->d_un.d_ptr);
                break;
            case DT_STRTAB:
                strtab = (const char*)(base + dyn->d_un.d_ptr);
                break;
        }
    }
    
    numsyms = ((uintptr_t)strtab - (uintptr_t)symtab) / sizeof(Elf64_Sym);
    
    for (uint64_t i = 0; i < numsyms; i++)
    {
        char* demangled = abi::__cxa_demangle(strtab + symtab[i].st_name, 0, 0, 0);

        if (symtab[i].st_shndx == 0 && demangled)
        {
            //TODO: just read the main NSO for types/sizes? Or have them resolve to the main NSO

            uint64_t import_size = 0x8;
            std::string demangled_str = std::string(demangled);
            if (demangled_str == "phx::detail::CRC32Table::table_")
            {
                import_size = 0x100;
            }
            else if (demangled_str == "lib::L2CValue::NIL")
            {
                import_size = 0x10;
            }
            else if (!strncmp(demangled, "`vtable for'", 12))
            {
                import_size = 0x1000;
            }
            
            uint64_t addr = IMPORTS + (imports_size + import_size);
            unresolved_syms[std::string(demangled_str)] = addr;
            unresolved_syms_rev[addr] = std::string(demangled);
            
            imports_size += import_size;
        }
        else if (symtab[i].st_shndx && demangled)
        {
            resolved_syms[std::string(demangled)] = NRO + symtab[i].st_value;
        }
        else
        {

        }
        free(demangled);
    }
    
    syms_scanned = true;
}

void nro_relocate(void* base)
{
    const Elf64_Dyn* dyn = NULL;
    const Elf64_Rela* rela = NULL;
    const Elf64_Sym* symtab = NULL;
    const char* strtab = NULL;
    uint64_t relasz = 0;
    uint64_t numsyms = 0;
    
    struct nso_header* header = (struct nso_header*)base;
    struct mod0_header* modheader = (struct mod0_header*)(base + header->mod);
    dyn = (const Elf64_Dyn*)((void*)modheader + modheader->dynamic);

    for (; dyn->d_tag != DT_NULL; dyn++)
    {
        switch (dyn->d_tag)
        {
            case DT_SYMTAB:
                symtab = (const Elf64_Sym*)(base + dyn->d_un.d_ptr);
                break;
            case DT_STRTAB:
                strtab = (const char*)(base + dyn->d_un.d_ptr);
                break;
            case DT_RELA:
                rela = (const Elf64_Rela*)(base + dyn->d_un.d_ptr);
                break;
            case DT_RELASZ:
                relasz += dyn->d_un.d_val / sizeof(Elf64_Rela);
                break;
            case DT_PLTRELSZ:
                relasz += dyn->d_un.d_val / sizeof(Elf64_Rela);
                break;
        }
    }
    
    if (rela == NULL)
    {
        return;
    }

    for (; relasz--; rela++)
    {
        uint32_t sym_idx = ELF64_R_SYM(rela->r_info);
        const char* name = strtab + symtab[sym_idx].st_name;

        uint64_t sym_val = (uint64_t)base + symtab[sym_idx].st_value;
        if (!symtab[sym_idx].st_value)
            sym_val = 0;

        switch (ELF64_R_TYPE(rela->r_info))
        {
            case R_AARCH64_RELATIVE:
            {
                uint64_t* ptr = (uint64_t*)(base + rela->r_offset);
                *ptr = NRO + rela->r_addend;
                break;
            }
            case R_AARCH64_GLOB_DAT:
            case R_AARCH64_JUMP_SLOT:
            case R_AARCH64_ABS64:
            {
                uint64_t* ptr = (uint64_t*)(base + rela->r_offset);
                char* demangled = abi::__cxa_demangle(name, 0, 0, 0);
                
                if (demangled)
                {
                    //printf("@ %" PRIx64 ", %s -> %" PRIx64 ", %" PRIx64 "\n", NRO + rela->r_offset, demangled, unresolved_syms[std::string(demangled)], *ptr);
                    if (resolved_syms[std::string(demangled)])
                        *ptr = resolved_syms[std::string(demangled)];
                    else
                        *ptr = unresolved_syms[std::string(demangled)];
                    free(demangled);
                }
                break;
            }
            default:
            {
                printf("Unknown relocation type %" PRId32 "\n", ELF64_R_TYPE(rela->r_info));
                break;
            }
        }
    }
}

uint64_t hash40(const void* data, size_t len)
{
    return crc32(data, len) | (len & 0xFF) << 32;
}

void uc_read_reg_state(uc_engine *uc, struct uc_reg_state *regs)
{
    uc_reg_read(uc, UC_ARM64_REG_X0, &regs->x0);
    uc_reg_read(uc, UC_ARM64_REG_X1, &regs->x1);
    uc_reg_read(uc, UC_ARM64_REG_X2, &regs->x2);
    uc_reg_read(uc, UC_ARM64_REG_X3, &regs->x3);
    uc_reg_read(uc, UC_ARM64_REG_X4, &regs->x4);
    uc_reg_read(uc, UC_ARM64_REG_X5, &regs->x5);
    uc_reg_read(uc, UC_ARM64_REG_X6, &regs->x6);
    uc_reg_read(uc, UC_ARM64_REG_X7, &regs->x7);
    uc_reg_read(uc, UC_ARM64_REG_X8, &regs->x8);
    uc_reg_read(uc, UC_ARM64_REG_X9, &regs->x9);
    uc_reg_read(uc, UC_ARM64_REG_X10, &regs->x10);
    uc_reg_read(uc, UC_ARM64_REG_X11, &regs->x11);
    uc_reg_read(uc, UC_ARM64_REG_X12, &regs->x12);
    uc_reg_read(uc, UC_ARM64_REG_X13, &regs->x13);
    uc_reg_read(uc, UC_ARM64_REG_X14, &regs->x14);
    uc_reg_read(uc, UC_ARM64_REG_X15, &regs->x15);
    uc_reg_read(uc, UC_ARM64_REG_X16, &regs->x16);
    uc_reg_read(uc, UC_ARM64_REG_X17, &regs->x17);
    uc_reg_read(uc, UC_ARM64_REG_X18, &regs->x18);
    uc_reg_read(uc, UC_ARM64_REG_X19, &regs->x19);
    uc_reg_read(uc, UC_ARM64_REG_X20, &regs->x20);
    uc_reg_read(uc, UC_ARM64_REG_X21, &regs->x21);
    uc_reg_read(uc, UC_ARM64_REG_X22, &regs->x22);
    uc_reg_read(uc, UC_ARM64_REG_X23, &regs->x23);
    uc_reg_read(uc, UC_ARM64_REG_X24, &regs->x24);
    uc_reg_read(uc, UC_ARM64_REG_X25, &regs->x25);
    uc_reg_read(uc, UC_ARM64_REG_X26, &regs->x26);
    uc_reg_read(uc, UC_ARM64_REG_X27, &regs->x27);
    uc_reg_read(uc, UC_ARM64_REG_X28, &regs->x28);
    uc_reg_read(uc, UC_ARM64_REG_FP, &regs->fp);
    uc_reg_read(uc, UC_ARM64_REG_LR, &regs->lr);
    uc_reg_read(uc, UC_ARM64_REG_SP, &regs->sp);
    uc_reg_read(uc, UC_ARM64_REG_PC, &regs->pc);
    
    uc_reg_read(uc, UC_ARM64_REG_S0, &regs->s0);
    uc_reg_read(uc, UC_ARM64_REG_S1, &regs->s1);
    uc_reg_read(uc, UC_ARM64_REG_S2, &regs->s2);
    uc_reg_read(uc, UC_ARM64_REG_S3, &regs->s3);
    uc_reg_read(uc, UC_ARM64_REG_S4, &regs->s4);
    uc_reg_read(uc, UC_ARM64_REG_S5, &regs->s5);
    uc_reg_read(uc, UC_ARM64_REG_S6, &regs->s6);
    uc_reg_read(uc, UC_ARM64_REG_S7, &regs->s7);
    uc_reg_read(uc, UC_ARM64_REG_S8, &regs->s8);
    uc_reg_read(uc, UC_ARM64_REG_S9, &regs->s9);
    uc_reg_read(uc, UC_ARM64_REG_S10, &regs->s10);
    uc_reg_read(uc, UC_ARM64_REG_S11, &regs->s11);
    uc_reg_read(uc, UC_ARM64_REG_S12, &regs->s12);
    uc_reg_read(uc, UC_ARM64_REG_S13, &regs->s13);
    uc_reg_read(uc, UC_ARM64_REG_S14, &regs->s14);
    uc_reg_read(uc, UC_ARM64_REG_S15, &regs->s15);
    uc_reg_read(uc, UC_ARM64_REG_S16, &regs->s16);
    uc_reg_read(uc, UC_ARM64_REG_S17, &regs->s17);
    uc_reg_read(uc, UC_ARM64_REG_S18, &regs->s18);
    uc_reg_read(uc, UC_ARM64_REG_S19, &regs->s19);
    uc_reg_read(uc, UC_ARM64_REG_S20, &regs->s20);
    uc_reg_read(uc, UC_ARM64_REG_S21, &regs->s21);
    uc_reg_read(uc, UC_ARM64_REG_S22, &regs->s22);
    uc_reg_read(uc, UC_ARM64_REG_S23, &regs->s23);
    uc_reg_read(uc, UC_ARM64_REG_S24, &regs->s24);
    uc_reg_read(uc, UC_ARM64_REG_S25, &regs->s25);
    uc_reg_read(uc, UC_ARM64_REG_S26, &regs->s26);
    uc_reg_read(uc, UC_ARM64_REG_S27, &regs->s27);
    uc_reg_read(uc, UC_ARM64_REG_S28, &regs->s28);
    uc_reg_read(uc, UC_ARM64_REG_S29, &regs->s29);
    uc_reg_read(uc, UC_ARM64_REG_S30, &regs->s30);
    uc_reg_read(uc, UC_ARM64_REG_S31, &regs->s31);
}

void uc_write_reg_state(uc_engine *uc, struct uc_reg_state *regs)
{
    uc_reg_write(uc, UC_ARM64_REG_X0, &regs->x0);
    uc_reg_write(uc, UC_ARM64_REG_X1, &regs->x1);
    uc_reg_write(uc, UC_ARM64_REG_X2, &regs->x2);
    uc_reg_write(uc, UC_ARM64_REG_X3, &regs->x3);
    uc_reg_write(uc, UC_ARM64_REG_X4, &regs->x4);
    uc_reg_write(uc, UC_ARM64_REG_X5, &regs->x5);
    uc_reg_write(uc, UC_ARM64_REG_X6, &regs->x6);
    uc_reg_write(uc, UC_ARM64_REG_X7, &regs->x7);
    uc_reg_write(uc, UC_ARM64_REG_X8, &regs->x8);
    uc_reg_write(uc, UC_ARM64_REG_X9, &regs->x9);
    uc_reg_write(uc, UC_ARM64_REG_X10, &regs->x10);
    uc_reg_write(uc, UC_ARM64_REG_X11, &regs->x11);
    uc_reg_write(uc, UC_ARM64_REG_X12, &regs->x12);
    uc_reg_write(uc, UC_ARM64_REG_X13, &regs->x13);
    uc_reg_write(uc, UC_ARM64_REG_X14, &regs->x14);
    uc_reg_write(uc, UC_ARM64_REG_X15, &regs->x15);
    uc_reg_write(uc, UC_ARM64_REG_X16, &regs->x16);
    uc_reg_write(uc, UC_ARM64_REG_X17, &regs->x17);
    uc_reg_write(uc, UC_ARM64_REG_X18, &regs->x18);
    uc_reg_write(uc, UC_ARM64_REG_X19, &regs->x19);
    uc_reg_write(uc, UC_ARM64_REG_X20, &regs->x20);
    uc_reg_write(uc, UC_ARM64_REG_X21, &regs->x21);
    uc_reg_write(uc, UC_ARM64_REG_X22, &regs->x22);
    uc_reg_write(uc, UC_ARM64_REG_X23, &regs->x23);
    uc_reg_write(uc, UC_ARM64_REG_X24, &regs->x24);
    uc_reg_write(uc, UC_ARM64_REG_X25, &regs->x25);
    uc_reg_write(uc, UC_ARM64_REG_X26, &regs->x26);
    uc_reg_write(uc, UC_ARM64_REG_X27, &regs->x27);
    uc_reg_write(uc, UC_ARM64_REG_X28, &regs->x28);
    uc_reg_write(uc, UC_ARM64_REG_FP, &regs->fp);
    uc_reg_write(uc, UC_ARM64_REG_LR, &regs->lr);
    uc_reg_write(uc, UC_ARM64_REG_SP, &regs->sp);
    uc_reg_write(uc, UC_ARM64_REG_PC, &regs->pc);
    
    uc_reg_write(uc, UC_ARM64_REG_S0, &regs->s0);
    uc_reg_write(uc, UC_ARM64_REG_S1, &regs->s1);
    uc_reg_write(uc, UC_ARM64_REG_S2, &regs->s2);
    uc_reg_write(uc, UC_ARM64_REG_S3, &regs->s3);
    uc_reg_write(uc, UC_ARM64_REG_S4, &regs->s4);
    uc_reg_write(uc, UC_ARM64_REG_S5, &regs->s5);
    uc_reg_write(uc, UC_ARM64_REG_S6, &regs->s6);
    uc_reg_write(uc, UC_ARM64_REG_S7, &regs->s7);
    uc_reg_write(uc, UC_ARM64_REG_S8, &regs->s8);
    uc_reg_write(uc, UC_ARM64_REG_S9, &regs->s9);
    uc_reg_write(uc, UC_ARM64_REG_S10, &regs->s10);
    uc_reg_write(uc, UC_ARM64_REG_S11, &regs->s11);
    uc_reg_write(uc, UC_ARM64_REG_S12, &regs->s12);
    uc_reg_write(uc, UC_ARM64_REG_S13, &regs->s13);
    uc_reg_write(uc, UC_ARM64_REG_S14, &regs->s14);
    uc_reg_write(uc, UC_ARM64_REG_S15, &regs->s15);
    uc_reg_write(uc, UC_ARM64_REG_S16, &regs->s16);
    uc_reg_write(uc, UC_ARM64_REG_S17, &regs->s17);
    uc_reg_write(uc, UC_ARM64_REG_S18, &regs->s18);
    uc_reg_write(uc, UC_ARM64_REG_S19, &regs->s19);
    uc_reg_write(uc, UC_ARM64_REG_S20, &regs->s20);
    uc_reg_write(uc, UC_ARM64_REG_S21, &regs->s21);
    uc_reg_write(uc, UC_ARM64_REG_S22, &regs->s22);
    uc_reg_write(uc, UC_ARM64_REG_S23, &regs->s23);
    uc_reg_write(uc, UC_ARM64_REG_S24, &regs->s24);
    uc_reg_write(uc, UC_ARM64_REG_S25, &regs->s25);
    uc_reg_write(uc, UC_ARM64_REG_S26, &regs->s26);
    uc_reg_write(uc, UC_ARM64_REG_S27, &regs->s27);
    uc_reg_write(uc, UC_ARM64_REG_S28, &regs->s28);
    uc_reg_write(uc, UC_ARM64_REG_S29, &regs->s29);
    uc_reg_write(uc, UC_ARM64_REG_S30, &regs->s30);
    uc_reg_write(uc, UC_ARM64_REG_S31, &regs->s31);
}

void uc_print_regs(uc_engine *uc)
{
    uint64_t x0, x1, x2, x3, x4, x5 ,x6 ,x7, x8;
    uint64_t x9, x10, x11, x12, x13, x14, x15, x16;
    uint64_t x17, x18, x19, x20, x21, x22, x23, x24;
    uint64_t x25, x26, x27, x28, fp, lr, sp, pc;
    
    if (!logmask_is_set(LOGMASK_DEBUG)) return;
    
    uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
    uc_reg_read(uc, UC_ARM64_REG_X1, &x1);
    uc_reg_read(uc, UC_ARM64_REG_X2, &x2);
    uc_reg_read(uc, UC_ARM64_REG_X3, &x3);
    uc_reg_read(uc, UC_ARM64_REG_X4, &x4);
    uc_reg_read(uc, UC_ARM64_REG_X5, &x5);
    uc_reg_read(uc, UC_ARM64_REG_X6, &x6);
    uc_reg_read(uc, UC_ARM64_REG_X7, &x7);
    uc_reg_read(uc, UC_ARM64_REG_X8, &x8);
    uc_reg_read(uc, UC_ARM64_REG_X9, &x9);
    uc_reg_read(uc, UC_ARM64_REG_X10, &x10);
    uc_reg_read(uc, UC_ARM64_REG_X11, &x11);
    uc_reg_read(uc, UC_ARM64_REG_X12, &x12);
    uc_reg_read(uc, UC_ARM64_REG_X13, &x13);
    uc_reg_read(uc, UC_ARM64_REG_X14, &x14);
    uc_reg_read(uc, UC_ARM64_REG_X15, &x15);
    uc_reg_read(uc, UC_ARM64_REG_X16, &x16);
    uc_reg_read(uc, UC_ARM64_REG_X17, &x17);
    uc_reg_read(uc, UC_ARM64_REG_X18, &x18);
    uc_reg_read(uc, UC_ARM64_REG_X19, &x19);
    uc_reg_read(uc, UC_ARM64_REG_X20, &x20);
    uc_reg_read(uc, UC_ARM64_REG_X21, &x21);
    uc_reg_read(uc, UC_ARM64_REG_X22, &x22);
    uc_reg_read(uc, UC_ARM64_REG_X23, &x23);
    uc_reg_read(uc, UC_ARM64_REG_X24, &x24);
    uc_reg_read(uc, UC_ARM64_REG_X25, &x25);
    uc_reg_read(uc, UC_ARM64_REG_X26, &x26);
    uc_reg_read(uc, UC_ARM64_REG_X27, &x27);
    uc_reg_read(uc, UC_ARM64_REG_X28, &x28);
    uc_reg_read(uc, UC_ARM64_REG_FP, &fp);
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
    uc_reg_read(uc, UC_ARM64_REG_SP, &sp);
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc);

    printf_debug("Register dump:\n");
    printf_debug("x0  %16.16" PRIx64 " ", x0);
    printf("x1  %16.16" PRIx64 " ", x1);
    printf("x2  %16.16" PRIx64 " ", x2);
    printf("x3  %16.16" PRIx64 " ", x3);
    printf("\n");
    printf_debug("x4  %16.16" PRIx64 " ", x4);
    printf("x5  %16.16" PRIx64 " ", x5);
    printf("x6  %16.16" PRIx64 " ", x6);
    printf("x7  %16.16" PRIx64 " ", x7);
    printf("\n");
    printf_debug("x8  %16.16" PRIx64 " ", x8);
    printf("x9  %16.16" PRIx64 " ", x9);
    printf("x10 %16.16" PRIx64 " ", x10);
    printf("x11 %16.16" PRIx64 " ", x11);
    printf("\n");
    printf_debug("x12 %16.16" PRIx64 " ", x12);
    printf("x13 %16.16" PRIx64 " ", x13);
    printf("x14 %16.16" PRIx64 " ", x14);
    printf("x15 %16.16" PRIx64 " ", x15);
    printf("\n");
    printf_debug("x16 %16.16" PRIx64 " ", x16);
    printf("x17 %16.16" PRIx64 " ", x17);
    printf("x18 %16.16" PRIx64 " ", x18);
    printf("x19 %16.16" PRIx64 " ", x19);
    printf("\n");
    printf_debug("x20 %16.16" PRIx64 " ", x20);
    printf("x21 %16.16" PRIx64 " ", x21);
    printf("x22 %16.16" PRIx64 " ", x22);
    printf("x23 %16.16" PRIx64 " ", x23);
    printf("\n");
    printf_debug("x24 %16.16" PRIx64 " ", x24);
    printf("x25 %16.16" PRIx64 " ", x25);
    printf("x26 %16.16" PRIx64 " ", x26);
    printf("x27 %16.16" PRIx64 " ", x27);
    printf("\n");
    printf_debug("x28 %16.16" PRIx64 " ", x28);
    printf("\n");
    printf_debug("fp  %16.16" PRIx64 " ", fp);
    printf("lr  %16.16" PRIx64 " ", lr);
    printf("sp  %16.16" PRIx64 " ", sp);
    printf("pc  %16.16" PRIx64 " ", pc);
    
    
    printf("\n");
}

void hook_code(uc_engine *uc, uint64_t address, uint32_t size, uc_inst* inst)
{
    static uint64_t last_pc[2];

    if (last_pc[0] == address && last_pc[0] == last_pc[1] && !inst->is_term())
    {
        printf_warn("Hang at 0x%" PRIx64 " ?\n", address);
        inst->terminate();
    }

    if (trace_code && !inst->is_term())
    {
        //printf(">>> Tracing instruction at 0x%" PRIx64 ", instruction size = 0x%x\n", address, size);
        //uc_print_regs(uc);
    }
    
    last_pc[1] = last_pc[0];
    last_pc[0] = address;
}

void remove_matching_tokens(uint64_t addr, std::string str)
{
    for (auto& pair : tokens)
    {
        std::vector<L2C_Token> to_erase;
        for (auto& t : pair.second)
        {
            if (t.pc == addr && t.str == str)
            {
                to_erase.push_back(t);
            }
        }

        for (auto& t : to_erase)
        {
            pair.second.erase(t);
        }
    }
}

void remove_block_matching_tokens(uint64_t block, uint64_t addr, std::string str)
{
    std::vector<L2C_Token> to_erase;
    for (auto& t : tokens[block])
    {
        if (t.pc == addr && t.str == str)
        {
            to_erase.push_back(t);
        }
    }

    for (auto& t : to_erase)
    {
        tokens[block].erase(t);
    }
}

bool token_by_addr_and_name_exists(uint64_t pc, std::string str)
{
    for (auto& pair : tokens)
    {
        for (auto& t : pair.second)
        {
            if (t.pc == pc && t.str == str)
            {
                return true;
            }
        }
    }
    
    return false;
}

void add_token_by_prio(uc_inst* inst, uint64_t block, L2C_Token token)
{
    for (auto& pair : tokens)
    {
        std::set<L2C_Token> to_erase;
        for (auto& t : pair.second)
        {
            if (t.pc == token.pc && t.str == token.str && token.fork_hierarchy.size() < t.fork_hierarchy.size())
            {
                to_erase.insert(t);
            }
            else if (t.pc == token.pc && t.str == token.str && token.fork_hierarchy.size() == t.fork_hierarchy.size() && t.fork_hierarchy[0] > token.fork_hierarchy[0])
            {
                to_erase.insert(t);
            }
            else if (t.pc == token.pc && t.str == token.str && token.fork_hierarchy.size() > t.fork_hierarchy.size())
            {
                return;
            }
        }

        for (auto& t : to_erase)
        {
            pair.second.erase(t);
        }
    }

    //printf("%llx\n", block);
    //token.print();

    tokens[block].insert(token);
    inst->inc_outputted_tokens();
}

void add_subreplace_token(uc_inst* inst, uint64_t block, L2C_Token token)
{
    std::set<L2C_Token> to_erase;
    for (auto& t : tokens[block])
    {
        if ((t.pc == token.pc && t.str == "SUB_BRANCH") 
            || (t.str == "SUB_GOTO" && t.args[0] == inst->get_current_block()))
        {
            to_erase.insert(t);
        }
    }

    bool function_tail = false;
    for (auto& t : to_erase)
    {
        tokens[block].erase(t);
        
        if (t.str == "SUB_GOTO")
            function_tail = true;
    }

    add_token_by_prio(inst, block, token);
    
    if (function_tail)
    {
        token.str = "SUB_RET";
        token.type = L2C_TokenType_Meta;
        token.args.clear();
        token.fargs.clear();
        add_token_by_prio(inst, block, token);
        
        inst->pop_block();
        
        if (token.pc+4 >= blocks[block].addr_end)
            blocks[block].addr_end = token.pc+4;
    }
}

uint64_t find_containing_block(uint64_t addr)
{
    for (auto& block_pair : blocks)
    {
        auto& block = block_pair.second;

        if (addr >= block.addr && addr < block.addr_end)
        {
            return block.addr;
        }
    }
    
    return 0;
}

void hook_import(uc_engine *uc, uint64_t address, uint32_t size, uc_inst* inst)
{
    uint64_t lr, origin;
    std::string name = unresolved_syms_rev[address];
    
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
    origin = inst->get_jump_history();
    printf_verbose("Instance Id %u: Import '%s' from %" PRIx64 ", size %x, block %" PRIx64 "\n", inst->get_id(), name.c_str(), origin, size, inst->get_last_block());
    invalidate_blocktree(inst, inst->get_current_block());
    
    // Add token
    L2C_Token token;
    token.pc = origin;
    token.fork_hierarchy = inst->get_fork_hierarchy();
    token.str = name;
    token.type = L2C_TokenType_Func;

    if (!inst->is_basic_emu() && converge_points[origin] && inst->has_parent() && inst->get_start_addr())
    {
        // Don't terminate if the token at the convergence point has a larger fork hierarchy
        // Too large a fork hierarchy just means one of the forks got ahead of the root
        // instance and the tokens will be replaced by correct values.
        bool should_term = false;
        uint64_t term_block = 0;
        for (auto& pair : tokens)
        {
            for (auto& t : pair.second)
            {
                //if (t.pc == origin)
                    //printf("conv %u: %llx %s %zx %zx\n", inst->get_id(), t.pc, t.str.c_str(), token.fork_hierarchy.size(), t.fork_hierarchy.size());
                if (t.pc == origin && (t.type == L2C_TokenType_Func || t.type == L2C_TokenType_Branch))
                {
                    if (token.fork_hierarchy.size() > t.fork_hierarchy.size())
                    {
                        //printf("doconv %u: %llx %s\n", inst->get_id(), t.pc, t.str.c_str());
                        should_term = true;
                        term_block = pair.first;
                    }
                    else if (token.fork_hierarchy.size() == t.fork_hierarchy.size())
                    {
                        should_term = token.fork_hierarchy[0] >= t.fork_hierarchy[0];
                        term_block = pair.first;
                    }
                }
                
                if (should_term) break;
            }
            if (should_term) break;
        }
        
        if (should_term)
        {
            printf_debug("Instance Id %u: Found convergence at %" PRIx64 ", outputted %u tokens\n", inst->get_id(), origin, inst->num_outputted_tokens());
            
            //TODO: split blocks
            if (inst->get_last_block() != term_block)
            {
                printf_warn("Instance Id %u: Convergence block is not the same as current block (%" PRIx64 ", %" PRIx64 ")...\n", inst->get_id(), inst->get_last_block(), term_block);
            }
            
            token.str = "CONV";
            token.type = L2C_TokenType_Meta;
            
            token.args.push_back(origin);
            token.args.push_back(term_block);
            //token.args.push_back(next_closest_block(inst->get_last_block(), origin));
            
            // Sometimes we get branches which just do nothing, pretend they don't exist
            if (inst->num_outputted_tokens())
                add_token_by_prio(inst, inst->get_last_block(), token);
            inst->terminate();
            return;
        }
    }

    bool add_token = false;
    if (!inst->is_basic_emu() && converge_points[origin])
    {
        for (auto& pair : tokens)
        {
            std::set<L2C_Token> to_erase;
            for (auto& t : pair.second)
            {
                if (t.pc == origin && t.type == L2C_TokenType_Func)
                {
                    if (token.fork_hierarchy.size() < t.fork_hierarchy.size())
                    {
                        to_erase.insert(t);
                        add_token = true;
                    }
                    else if (token.fork_hierarchy.size() == t.fork_hierarchy.size()
                             && token.fork_hierarchy[0] < t.fork_hierarchy[0])
                    {
                        to_erase.insert(t);
                        add_token = true;
                    }
                }
            }
            
            for (auto& t : to_erase)
            {
                pair.second.erase(t);
            }
        }
    }
    else if (!inst->is_basic_emu())
    {
        add_token = true;
    }

    // Write out a magic PC val which will cause Unicorn to fault.
    // This allows for faster run time while there isn't a fork,
    // since more instructions can be ran at once.
    // Also helps to synchronize fork+parent PC vals when a fork
    // does happen.
    uint64_t magic = MAGIC_IMPORT;
    uc_reg_write(uc, UC_ARM64_REG_PC, &magic);
    
    uint64_t args[9];
    float fargs[9];
    uc_reg_read(uc, UC_ARM64_REG_X0, &args[0]);
    uc_reg_read(uc, UC_ARM64_REG_X1, &args[1]);
    uc_reg_read(uc, UC_ARM64_REG_X2, &args[2]);
    uc_reg_read(uc, UC_ARM64_REG_X3, &args[3]);
    uc_reg_read(uc, UC_ARM64_REG_X4, &args[4]);
    uc_reg_read(uc, UC_ARM64_REG_X5, &args[5]);
    uc_reg_read(uc, UC_ARM64_REG_X6, &args[6]);
    uc_reg_read(uc, UC_ARM64_REG_X7, &args[7]);
    uc_reg_read(uc, UC_ARM64_REG_X8, &args[8]);
    
    uc_reg_read(uc, UC_ARM64_REG_S0, &fargs[0]);
    uc_reg_read(uc, UC_ARM64_REG_S1, &fargs[1]);
    uc_reg_read(uc, UC_ARM64_REG_S2, &fargs[2]);
    uc_reg_read(uc, UC_ARM64_REG_S3, &fargs[3]);
    uc_reg_read(uc, UC_ARM64_REG_S4, &fargs[4]);
    uc_reg_read(uc, UC_ARM64_REG_S5, &fargs[5]);
    uc_reg_read(uc, UC_ARM64_REG_S6, &fargs[6]);
    uc_reg_read(uc, UC_ARM64_REG_S7, &fargs[7]);
    uc_reg_read(uc, UC_ARM64_REG_S8, &fargs[8]);

    converge_points[origin] = true;
    
    if (name == "operator new(unsigned long)")
    {
        uint64_t alloc = inst->heap_alloc(args[0]);
        
        //TODO
        if (args[0] > 0x48)
            hash_cheat_ptr = alloc;
        
        args[0] = alloc;
    }
    else if (name == "lib::L2CAgent::sv_set_function_hash(void*, phx::Hash40)")
    {
        printf_info("Instance Id %u: lib::L2CAgent::sv_set_function_hash(0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64 ")\n", inst->get_id(), args[0], args[1], args[2]);
        
        function_hashes[std::pair<uint64_t, uint64_t>(args[0], args[2])] = args[1];
    }
    else if (name == "lua2cpp::L2CAgentBase::sv_set_status_func(lib::L2CValue const&, lib::L2CValue const&, void*)")
    {
        L2CValue* a = (L2CValue*)inst->uc_ptr_to_real_ptr(args[1]);
        L2CValue* b = (L2CValue*)inst->uc_ptr_to_real_ptr(args[2]);
        uint64_t funcptr = args[3];
        
        uint64_t fakehash = a->raw << 32 | b->raw;
        std::string kind = fighter_status_kind[a->raw + 1];
        if (kind == "")
            kind = std::to_string(a->raw);

        std::string unhash_str = kind + "__" + status_func[b->raw];
        unhash[fakehash] = unhash_str;
        
        printf("Instance Id %u: lua2cpp::L2CAgentBase::sv_set_status_func(0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64 ") -> %s,%10" PRIx64 "\n", inst->get_id(), args[0], a->raw, b->raw, funcptr, unhash_str.c_str(), fakehash);
        
        function_hashes[std::pair<uint64_t, uint64_t>(args[0], fakehash)] = funcptr;
    }
    else if (name == "lib::utility::Variadic::get_format() const")
    {
        args[0] = 0;
    }
    else if (name == "lib::L2CAgent::clear_lua_stack()")
    {
        inst->lua_stack = std::vector<L2CValue>();
    }
    else if (name == "app::sv_animcmd::is_excute(lua_State*)")
    {
        inst->lua_stack.push_back(L2CValue(true));
    }
    else if (name == "app::sv_animcmd::frame(lua_State*, float)")
    {
        token.args.push_back(args[0]);
        token.fargs.push_back(fargs[0]);

        inst->lua_stack.push_back(L2CValue(true));
    }
    else if (name == "lib::L2CAgent::pop_lua_stack(int)")
    {
        token.args.push_back(args[1]);
    
        L2CValue* out = (L2CValue*)inst->uc_ptr_to_real_ptr(args[8]);
        L2CValue* iter = out;

        for (int i = 0; i < args[1]; i++)
        {
            if (!out) break;

            if (inst->lua_stack.size())
            {
                *iter = *(inst->lua_stack.end() - 1);
                inst->lua_stack.pop_back();
            }
            else
            {
                //printf_warn("Instance Id %u: Bad stack pop...\n", inst->get_id());
                
                L2CValue empty();
                *iter = empty;
            }

            iter++;
        }
        
        //inst->lua_active_vars[args[8]] = out;
    }
    else if (name == "lib::L2CAgent::push_lua_stack(lib::L2CValue const&)")
    {
        L2CValue* val = (L2CValue*)inst->uc_ptr_to_real_ptr(args[1]);
        
        if (val)
        {
            token.args.push_back(val->type);
            if (val->type != L2C_number)
            {
                token.args.push_back(val->raw);
            }
            else
            {
                token.fargs.push_back(val->as_number());
            }
            
        }
    }
    else if (name == "lib::L2CValue::L2CValue(int)")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);
        if (var)
            *var = L2CValue((int)args[1]);
        else
            printf_error("Instance Id %u: Bad L2CValue init, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    
        token.args.push_back((int)args[1]);
        //add_token = false;
        //purge_markers(token.pc);
    }
    else if (name == "lib::L2CValue::L2CValue(long)")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);
        if (var)
            *var = L2CValue((long)args[1]);
        else
            printf_error("Instance Id %u: Bad L2CValue init, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    
        token.args.push_back((long)args[1]);
        //add_token = false;
        //purge_markers(token.pc);
    }
    else if (name == "lib::L2CValue::L2CValue(unsigned int)"
             || name == "lib::L2CValue::L2CValue(unsigned long)")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);
        if (var)
            *var = L2CValue(args[1]);
        else
            printf_error("Instance Id %u: Bad L2CValue init, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    
        token.args.push_back(args[1]);
        //add_token = false;
        //purge_markers(token.pc);
    }
    else if (name == "lib::L2CValue::L2CValue(bool)")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);
        if (var)
            *var = L2CValue((bool)args[1]);
        else
            printf_error("Instance Id %u: Bad L2CValue init, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    
        token.args.push_back((int)args[1]);
        //add_token = false;
        //purge_markers(token.pc);
    }
    else if (name == "lib::L2CValue::L2CValue(phx::Hash40)")
    {
        Hash40 hash = {args[1] & 0xFFFFFFFFFF};
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);
        if (var)
            *var = L2CValue(hash);
        else
            printf_error("Instance Id %u: Bad L2CValue init, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
        
        token.args.push_back(hash.hash);
        //add_token = false;
        //purge_markers(token.pc);
    }
    else if (name == "lib::L2CValue::L2CValue(void*)")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);
        if (var)
            *var = L2CValue((void*)args[1]);
        else
            printf_error("Instance Id %u: Bad L2CValue init, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
        
        token.args.push_back(args[1]);
        //add_token = false;
        //purge_markers(token.pc);
    }
    else if (name == "lib::L2CValue::L2CValue(float)")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);
        if (var)
            *var = L2CValue((float)fargs[0]);
        else
            printf_error("Instance Id %u: Bad L2CValue init, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
        
        token.fargs.push_back(fargs[0]);
        //add_token = false;
        //purge_markers(token.pc);
    }
    else if (name == "lib::L2CValue::as_number() const")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);

        if (var)
        {
            fargs[0] = var->as_number();
            token.fargs.push_back(var->as_number());
        }
        else
            printf_error("Instance Id %u: Bad L2CValue access, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    }
    else if (name == "lib::L2CValue::as_bool() const")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);

        if (var)
        {
            args[0] = var->as_bool();
            token.args.push_back(var->as_bool());
        }
        else
            printf_error("Instance Id %u: Bad L2CValue access, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    }
    else if (name == "lib::L2CValue::as_integer() const")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);

        if (var)
        {
            args[0] = var->as_integer();
            token.args.push_back(var->as_integer());
        }
        else
            printf_error("Instance Id %u: Bad L2CValue access, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    }
    else if (name == "lib::L2CValue::as_pointer() const")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);

        if (var)
        {
            args[0] = var->raw;
            token.args.push_back(var->raw);
        }
        else
            printf_error("Instance Id %u: Bad L2CValue access, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    }
    else if (name == "lib::L2CValue::as_table() const")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);

        if (var)
        {
            args[0] = var->raw;
            token.args.push_back(var->raw);
        }
        else
            printf_error("Instance Id %u: Bad L2CValue access, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    }
    else if (name == "lib::L2CValue::as_inner_function() const")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);

        if (var)
        {
            args[0] = var->raw;
            token.args.push_back(var->raw);
        }
        else
            printf_error("Instance Id %u: Bad L2CValue access, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    }
    else if (name == "lib::L2CValue::as_hash() const")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);

        if (var)
        {
            args[0] = var->as_hash();
            token.args.push_back(var->as_hash());
        }
        else
            printf_error("Instance Id %u: Bad L2CValue access, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    }
    else if (name == "lib::L2CValue::as_string() const")
    {
        L2CValue* var = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);

        if (var)
        {
            args[0] = var->raw;
            token.args.push_back(var->raw);
        }
        else
            printf_error("Instance Id %u: Bad L2CValue access, %" PRIx64 ", %" PRIx64 "\n", inst->get_id(), args[0], origin);
    }
    else if (name == "lib::L2CValue::~L2CValue()")
    {
        //inst->lua_active_vars[args[0]] = nullptr;
        //add_token = false;
        //purge_markers(token.pc);
    }
    else if (name == "lib::L2CValue::operator[](phx::Hash40) const")
    {
        if (!hash_cheat[args[1]])
        {
            hash_cheat[args[1]] = inst->heap_alloc(0x10);
        }

        uint64_t l2cval = hash_cheat[args[1]];
        hash_cheat_rev[l2cval] = args[1];

        printf_verbose("Hash cheating!! %llx\n", l2cval);
        
        args[0] = l2cval;
    }
    else if (name == "lib::L2CValue::operator=(lib::L2CValue const&)")
    {
        L2CValue* out = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);
        L2CValue* in = (L2CValue*)inst->uc_ptr_to_real_ptr(args[1]);
        
        if (in && out)
        {
            //TODO operator= destruction
            *out = *in;
            
            if (hash_cheat_rev[args[0]])
            {
                printf_verbose("Hash cheating! %llx => %llx\n", hash_cheat_rev[args[0]], in->raw);
                function_hashes[std::pair<uint64_t, uint64_t>(hash_cheat_ptr, hash_cheat_rev[args[0]])] = in->raw;
            }
        }
        else
        {
            printf_error("Instance Id %u: Bad L2CValue assignment @ " PRIx64 "!\n", inst->get_id(), origin);
        }
    }
    else if (name == "lib::L2CValue::operator bool() const"
             || name == "lib::L2CValue::operator==(lib::L2CValue const&) const"
             || name == "lib::L2CValue::operator<=(lib::L2CValue const&) const"
             || name == "lib::L2CValue::operator<(lib::L2CValue const&) const")
    {
        //TODO basic emu comparisons
        if (inst->is_basic_emu())
        {
            L2CValue* in = (L2CValue*)inst->uc_ptr_to_real_ptr(args[0]);
            if (in)
                args[0] = in->as_bool();
            else
                args[0] = 0;
        }
        else
        {
            if (add_token)
                add_subreplace_token(inst, inst->get_last_block(), token);
            add_token = false;

            args[0] = 1;
            uc_reg_write(uc, UC_ARM64_REG_X0, &args[0]);    
            inst->fork_inst();

            args[0] = 0;
        }
    }

    uc_reg_write(uc, UC_ARM64_REG_X0, &args[0]);
    uc_reg_write(uc, UC_ARM64_REG_X1, &args[1]);
    uc_reg_write(uc, UC_ARM64_REG_X2, &args[2]);
    uc_reg_write(uc, UC_ARM64_REG_X3, &args[3]);
    uc_reg_write(uc, UC_ARM64_REG_X4, &args[4]);
    uc_reg_write(uc, UC_ARM64_REG_X5, &args[5]);
    uc_reg_write(uc, UC_ARM64_REG_X6, &args[6]);
    uc_reg_write(uc, UC_ARM64_REG_X7, &args[7]);
    uc_reg_write(uc, UC_ARM64_REG_X8, &args[8]);
    
    uc_reg_write(uc, UC_ARM64_REG_S0, &fargs[0]);
    uc_reg_write(uc, UC_ARM64_REG_S1, &fargs[1]);
    uc_reg_write(uc, UC_ARM64_REG_S2, &fargs[2]);
    uc_reg_write(uc, UC_ARM64_REG_S3, &fargs[3]);
    uc_reg_write(uc, UC_ARM64_REG_S4, &fargs[4]);
    uc_reg_write(uc, UC_ARM64_REG_S5, &fargs[5]);
    uc_reg_write(uc, UC_ARM64_REG_S6, &fargs[6]);
    uc_reg_write(uc, UC_ARM64_REG_S7, &fargs[7]);
    uc_reg_write(uc, UC_ARM64_REG_S8, &fargs[8]);
    
    if (add_token)
        add_subreplace_token(inst, inst->get_last_block(), token);
}

void hook_memrw(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, uc_inst* inst)
{
    switch(type) 
    {
        default: break;
        case UC_MEM_READ:
                 value = *(uint64_t*)(inst->uc_ptr_to_real_ptr(addr));
                 printf_verbose("Instance Id %u: Memory is being READ at 0x%" PRIx64 ", data size = %u, data value = 0x%" PRIx64 "\n", inst->get_id(), addr, size, value);
                 break;
        case UC_MEM_WRITE:
                 printf_verbose("Instance Id %u: Memory is being WRITE at 0x%" PRIx64 ", data size = %u, data value = 0x%" PRIx64 "\n", inst->get_id(), addr, size, value);
                 break;
    }
    return;
}

// callback for tracing memory access (READ or WRITE)
bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, uc_inst* inst)
{
    switch(type) {
        default:
            // return false to indicate we want to stop emulation
            return false;
        case UC_MEM_READ_UNMAPPED:
            printf_error("Instance Id %u: Missing memory is being READ at 0x%" PRIx64 ", data size = %u, data value = 0x%" PRIx64 " PC @ %" PRIx64 "\n", inst->get_id(), address, size, value, inst->get_pc());
            //uc_print_regs(uc);
            
            return false;
        case UC_MEM_WRITE_UNMAPPED:        
            printf_error("Instance Id %u: Missing memory is being WRITE at 0x%" PRIx64 ", data size = %u, data value = 0x%" PRIx64 " PC @ %" PRIx64 "\n", inst->get_id(), address, size, value, inst->get_pc());
            //uc_print_regs(uc);
            
            return true;
        case UC_ERR_EXCEPTION:
            if (address != MAGIC_IMPORT && inst->get_sp() != STACK_END)
                printf_error("Instance Id %u: Exception PC @ %" PRIx64 "\n", inst->get_id(), inst->get_pc());
            return false;
    }
}

void clean_and_verify_blocks(uint64_t func)
{
    std::map<uint64_t, bool> block_visited;
    std::vector<uint64_t> block_list;
    block_list.push_back(func);
    block_visited[func] = true;
    
    std::map<std::string, int> fork_token_instances;
    std::set<uint64_t> split_positions;
    std::map<uint64_t, bool> addr_in_block;
    std::map<uint64_t, bool> addr_in_token;
    
    while(block_list.size())
    {
        uint64_t b = *(block_list.end() - 1);
        block_list.pop_back();

        if (!tokens[b].size()) continue;

        L2C_Token last_token = L2C_Token();
        last_token.str = "";

        int num_jumps = 0;
        for (auto t : tokens[b])
        {
            if (t.str != "BLOCK_MERGE" && t.str != "SPLIT_BLOCK_MERGE" && t.str != "DIV_TRUE" && t.str != "SUB_RET")
            {
                if (addr_in_token[t.pc])
                    printf_warn("Token address overlap at %" PRIx64 " in block %" PRIx64 "\n", t.pc, b);

                addr_in_token[t.pc] = true;
            }
        
            if (t.str == "SUB_BRANCH" || t.str == "SUB_GOTO" || t.str == "DIV_FALSE" || t.str == "DIV_TRUE" || t.str == "CONV" || t.str == "BLOCK_MERGE" || t.str == "SPLIT_BLOCK_MERGE")
            {
                if (!block_visited[t.args[0]])
                {
                    block_list.push_back(t.args[0]);
                    block_visited[t.args[0]] = true;
                }
                
                if (!blocks[t.args[0]].num_tokens())
                {
                    printf_warn("Destination %" PRIx64 " from %s at %" PRIx64 " is empty!\n", t.args[0], t.str.c_str(), t.pc);
                }
            }
            
            if (t.str == "SUB_GOTO" || t.str == "DIV_FALSE" || t.str == "CONV" || t.str == "BLOCK_MERGE" || t.str == "SPLIT_BLOCK_MERGE" || t.str == "NORETURN" || t.str == "SUB_RET")
                num_jumps++;

            if (t.str == "DIV_TRUE" && last_token.str != "DIV_FALSE")
                printf_warn("Dangling DIV_TRUE at %" PRIx64 "\n", t.pc);

            if (last_token.str == "BLOCK_MERGE" || last_token.str == "SPLIT_BLOCK_MERGE" || last_token.str == "SUB_GOTO" || last_token.str == "CONV" || last_token.str == "DIV_TRUE")
            {
                printf_warn("%s found mid-block at %" PRIx64 " and not at end as expected!\n", last_token.str.c_str(), last_token.pc);
            }

            fork_token_instances[t.fork_hierarchy_str()]++;
            last_token = t;
        }
        
        if (last_token.str == "DIV_FALSE")
            printf_warn("Dangling DIV_FALSE at %" PRIx64 "\n", last_token.pc);
        
        for (uint64_t i = blocks[b].addr; i < blocks[b].addr_end; i += 4)
        {
            if (addr_in_block[i])
                printf_warn("Address range overlap at %" PRIx64 " in block %" PRIx64 "\n", i, b);
            addr_in_block[i] = true;
        }
        
        if (!num_jumps)
            printf_warn("Block %" PRIx64 " is missing an exit token!\n", b);
        else if (num_jumps > 1)
            printf_warn("Block %" PRIx64 " has too many exit tokens!\n", b);
        
        std::sort(block_list.begin(), block_list.end(), std::greater<int>()); 
    }
    
    for (auto& map_pair : fork_token_instances)
    {
        if (map_pair.second > 1) continue;

        for (auto& block_pair : tokens)
        {
            auto& block = block_pair.first;
            auto& block_tokens = block_pair.second;

            std::vector<L2C_Token> to_remove;
            for (auto& token : block_tokens)
            {
                std::string forkstr = token.fork_hierarchy_str();
                if (forkstr == map_pair.first && token.str == "CONV")
                {
                    to_remove.push_back(token);
                }
            }

            for (auto& token : to_remove)
            {
                if (logmask_is_set(LOGMASK_DEBUG))
                {
                    printf_debug("Pruning %s", token.to_string().c_str());
                }
                block_tokens.erase(token);
            }
        }
    }
}

std::map<uint64_t, bool> block_printed;

std::string print_block(uint64_t b)
{
    char tmp[256];
    std::string out = "";
    /*if (block_printed[b])
    {
        snprintf(tmp, 255, "\nBlock %" PRIx64 " type %u, size %x, %u tokens, creation %s: See earlier definition\n", blocks[b].hash(), blocks[b].type, blocks[b].size(), blocks[b].num_tokens(), blocks[b].fork_hierarchy_str().c_str());
        out += std::string(tmp);
        return out;
    }*/

    //snprintf(tmp, 255, "\nBlock %" PRIx64 " (end %" PRIx64 ") type %u, size %x, %u tokens, creation %s:\n", b, blocks[b].addr_end, blocks[b].type, blocks[b].size(), blocks[b].num_tokens(), blocks[b].fork_hierarchy_str().c_str());
    snprintf(tmp, 255, "\nBlock %" PRIx64 " type %u, size %x, %u tokens, creation %s:\n", blocks[b].hash(), blocks[b].type, blocks[b].size(), blocks[b].num_tokens(), blocks[b].fork_hierarchy_str().c_str());
    out += std::string(tmp);

    for (auto& t : tokens[b])
    {
        out += t.to_string(b);
    }
    
    block_printed[b] = true;
    
    return out;
}

std::string print_blocks(uint64_t func, std::unordered_map<uint64_t, bool>* block_visited = nullptr)
{
    char tmp[256];
    std::string out = "";
    std::map<uint64_t, bool> block_skipped;
    std::vector<uint64_t> block_visited_here;
    std::vector<uint64_t> block_list;
    block_list.push_back(func);

    bool needs_free = false;
    if (!block_visited)
    {
        block_visited = new std::unordered_map<uint64_t, bool>();
        needs_free = true;
    }
    
    if ((*block_visited)[func]) return "";
    
    (*block_visited)[func] = true;
    block_visited_here.push_back(func);

    while(block_list.size())
    {
        uint64_t b = *(block_list.end() - 1);
        block_list.pop_back();

        if (!tokens[b].size()) continue;

        //out += print_block(b);
        for (auto t : tokens[b])
        {
            if (t.str == "SUB_BRANCH" || t.str == "SUB_GOTO" || t.str == "DIV_FALSE" || t.str == "DIV_TRUE" || t.str == "CONV" || t.str == "BLOCK_MERGE" || t.str == "SPLIT_BLOCK_MERGE")
            {
                if (!(*block_visited)[t.args[0]] && !block_skipped[t.args[0]] && t.str != "SUB_BRANCH")
                {
                    block_list.push_back(t.args[0]);
                    (*block_visited)[t.args[0]] = true;
                    block_visited_here.push_back(t.args[0]);
                }
                else if (!(*block_visited)[t.args[0]])
                {
                    block_skipped[t.args[0]] = true;
                }
            }
        }
        
        //std::sort(block_list.begin(), block_list.end(), std::greater<int>());
    }
    
    for (auto b : block_visited_here)
    {
        out += print_block(b);
    }
    
    for (auto& pair : block_skipped)
    {
        uint64_t b = pair.first;
        
        out += print_blocks(b, block_visited);
    }
    
    if (needs_free) delete block_visited;
    
    return out;
}

void invalidate_blocktree(uc_inst* inst, uint64_t func)
{
    std::map<uint64_t, bool> block_visited;
    std::vector<uint64_t> block_list;
    block_list.push_back(func);
    block_visited[func] = true;
    
    //print_blocks(func);

    while(block_list.size())
    {
        uint64_t b = *(block_list.end() - 1);
        block_list.pop_back();

        if (!tokens[b].size()) continue;

        for (auto t : tokens[b])
        {
            if (t.str == "SUB_BRANCH" || t.str == "SUB_GOTO" || t.str == "DIV_FALSE" || t.str == "DIV_TRUE" || t.str == "CONV" || t.str == "BLOCK_MERGE" || t.str == "SPLIT_BLOCK_MERGE")
            {
                if (!block_visited[t.args[0]])
                {
                    block_list.push_back(t.args[0]);
                    block_visited[t.args[0]] = true;
                }
            }
        }
        
        std::sort(block_list.begin(), block_list.end(), std::greater<int>());
    }
    
    for (auto& pair : block_visited)
    {
        printf_verbose("Instance Id %u: Invalidated block %" PRIx64 " (type %u) from chain %" PRIx64 "\n", inst->get_id(), pair.first, blocks[pair.first].type, func);
    
        for (uint64_t i = blocks[pair.first].addr; i < blocks[pair.first].addr_end; i++)
        {
            converge_points[i] = false;
            is_goto_dst[i] = false;
            is_fork_origin[i] = false;
        }
    
        // In case there's anything weird going on...
        for (auto& t : tokens[pair.first])
        {
            converge_points[t.pc] = false;
            is_goto_dst[t.pc] = false;
            is_fork_origin[t.pc] = false;
        }
    
        tokens[pair.first].clear();
        blocks[pair.first] = L2C_CodeBlock();
    }
    printf_verbose("Instance Id %u: Invalidated %u block(s)\n", inst->get_id(), block_visited.size());
}

int main(int argc, char **argv, char **envp)
{
    char tmp[256];
    uint64_t x0, x1, x2, x3;
    x1 = 0xFFFE000000000000; // BattleObject
    x2 = 0xFFFD000000000000; // BattleObjectModuleAccessor
    x3 = 0xFFFC000000000000; // lua_state
    
    if (argc < 2)
    {
        printf("Usage: %s <lua2cpp_char.nro>\n", argv[0]);
        return -1;
    }

    init_character_objects();
    
    // Load in unhashed strings
    std::ifstream strings("hashstrings_lower.txt");    
    std::string line;
    while (std::getline(strings, line))
    {
        uint64_t crc = hash40((const void*)line.c_str(), strlen(line.c_str()));
        unhash[crc] = line;
    }
    
    uc_inst inst = uc_inst(std::string(argv[1]));
    
    // Scan exports to find the character name
    std::string character = "";
    for (auto& pair : resolved_syms)
    {
        std::string func = pair.first;
        char* match = "lua2cpp::create_agent_fighter_status_script_";
        
        
        if (!strncmp(func.c_str(), match, strlen(match)))
        {
            for (int i = strlen(match); i < func.length(); i++)
            {
                if (func[i] == '(') break;
                character += func[i];
            }
            break;
        }
    }

    std::map<std::string, uint64_t> l2cagents;
    std::map<uint64_t, std::string> l2cagents_rev;
    
    logmask_unset(LOGMASK_DEBUG | LOGMASK_INFO);
    //logmask_set(LOGMASK_VERBOSE);
    for (auto& agent : agents)
    {
        for (auto& object : character_objects[character])
        {
            std::string hashstr = object;
            std::string key = hashstr + "_" + agent;
            std::string func = "lua2cpp::create_agent_fighter_" + agent + "_" + character;
            std::string args = "(phx::Hash40, app::BattleObject*, app::BattleObjectModuleAccessor*, lua_State*)";
            
            x0 = hash40(hashstr.c_str(), hashstr.length()); // Hash40
            uint64_t funcptr = resolved_syms[func + args];
            if (!funcptr) continue;
            
            printf_debug("Running %s(hash40(%s) => 0x%08x, ...)...\n", func.c_str(), hashstr.c_str(), x0);
            uint64_t output = inst.uc_run_stuff(funcptr, false, false, x0, x1, x2, x3);
            
            if (output)
            {
                printf("Got output %" PRIx64 " for %s(hash40(%s) => 0x%08" PRIx64 ", ...), mapping to %s\n", output, func.c_str(), hashstr.c_str(), x0, key.c_str());
                l2cagents[key] = output;
                l2cagents_rev[output] = key;
                
                // Special MSC stuff, they store funcs in a vtable
                // so we run function 9 to actually set everything
                if (agent == "status_script")
                {
                    uint64_t vtable_ptr = *(uint64_t*)(inst.uc_ptr_to_real_ptr(output));
                    uint64_t* vtable = ((uint64_t*)(inst.uc_ptr_to_real_ptr(vtable_ptr)));
                    uint64_t func = vtable[9];

                    tokens.clear();
                    blocks.clear();
                    is_goto_dst.clear();
                    is_fork_origin.clear();
                    converge_points = std::map<uint64_t, bool>();
                    
                    inst.uc_run_stuff(func, true, true, output);
                }
            }
        }
    }
    //logmask_set(LOGMASK_DEBUG | LOGMASK_INFO);
    //logmask_set(LOGMASK_VERBOSE);

    // Set up L2CAgent
    //uint64_t l2cagent = inst.heap_alloc(0x1000);
    //L2CAgent* agent = (L2CAgent*)inst.uc_ptr_to_real_ptr(l2cagent);
    uint64_t luastate = inst.heap_alloc(0x1000);
    //agent->luastate = luastate;
    //lua_State* unk40 = (lua_State*)inst.uc_ptr_to_real_ptr(agent->luastate);
    
    for (int i = 0; i < 0x200; i += 8)
    {
        uint64_t class_alloc = inst.heap_alloc(0x100);
        uint64_t vtable_alloc = inst.heap_alloc(512 * sizeof(uint64_t));

        *(uint64_t*)(inst.uc_ptr_to_real_ptr(luastate + i)) = class_alloc;
        *(uint64_t*)(inst.uc_ptr_to_real_ptr(class_alloc)) = vtable_alloc;
        
        //printf("%llx %llx %llx\n", l2cagent, class_alloc, vtable_alloc);

        for (int j = 0; j < 512; j++)
        {
            uint64_t* out = (uint64_t*)inst.uc_ptr_to_real_ptr(vtable_alloc + j * sizeof(uint64_t));
            uint64_t addr = IMPORTS + (imports_size + 0x8);
            imports_size += 0x8;

            snprintf(tmp, 255, "lua_State::off%XVtableFunc%u", i, j);
            
            /*if (i == 0x40 && j == 0x39)
            {
                printf("%s %llx\n", tmp, addr);
            }*/
            
            std::string name(tmp);
            
            unresolved_syms[name] = addr;
            unresolved_syms_rev[addr] = name;
            *out = addr;
            
            inst.add_import_hook(addr);
        }
    }
    
    for (auto& pair : l2cagents)
    {
        uint64_t l2cagent = pair.second;
        L2CAgent* agent = (L2CAgent*)inst.uc_ptr_to_real_ptr(l2cagent);
        agent->lua_state_agent = luastate;
        agent->lua_state_agentbase = luastate;
    }
    
    for (auto& pair : function_hashes)
    {
        std::string out = "";
        auto regpair = pair.first;
        auto funcptr = pair.second;
        uint64_t hash = regpair.second;
  
        //if (regpair.first == l2cagents[character + "_status_script"])
        //if (regpair.first == l2cagents[character + "_animcmd_sound"])
        //if (funcptr == 0x1000ffe20)
        //if (funcptr == 0x1000eb140)
        //if (funcptr == 0x100101a20)
        {
            // String centering stuff

//#if 0
            out += ">--------------------------------------<\n";
            
            std::string agent_name = l2cagents_rev[regpair.first];
            for (int i = 0; i < 20 - (agent_name.length() / 2); i++)
            {
                out += " ";
            }
            out += agent_name + "\n";
            
            std::string func_name;
            if (unhash[hash] == "")
            {
                out += "               ";
                snprintf(tmp, 255, "%10" PRIx64, hash);
                func_name = std::string(tmp);
            }
            else
            {
                func_name = unhash[hash];
                for (int i = 0; i < 20 - (func_name.length() / 2); i++)
                {
                    out += " ";
                }
            }
            
            out += func_name + "\n";
//#endif
            //tokens.clear();
            //blocks.clear();
            is_goto_dst.clear();
            is_fork_origin.clear();
            converge_points = std::map<uint64_t, bool>();
            
            printf("%s/%s %" PRIx64 "\n", agent_name.c_str(), func_name.c_str()), funcptr;
            
            //printf("%s %10" PRIx64 " %8" PRIx64 "\n", l2cagents_rev[regpair.first].c_str(), hash, funcptr);
            inst.uc_run_stuff(funcptr, true, true, regpair.first, 0xFFFA000000000000);

//#if 0
            snprintf(tmp, 255, "                %8" PRIx64 "\n", blocks[funcptr].hash());
            out += std::string(tmp);
            out += ">--------------------------------------<\n";
//#endif

            out += print_blocks(funcptr);
            //out += print_block(funcptr);

//#if 0
            out += "<-------------------------------------->\n";
//#endif
            //printf("%s\n", out.c_str());
            
            std::string in = std::string(argv[1]);
            std::string dir_out = in.substr(0, in.find_last_of(".")) + "_out/" + agent_name;
            std::string file_out = dir_out + "/" + func_name + ".txt";
            try 
            {
                std::filesystem::create_directories(dir_out);
                std::ofstream file(file_out);
                file << out;
            }
            catch (std::exception& e) 
            {
                std::cout << e.what() << std::endl;
            }
            
            out = "";
        }
    }
    
    // Print all blocks
    /*for (auto& pair : tokens)
    {
        uint64_t block = pair.first;
        if (pair.second.size())
            print_block(block);
    }*/
    
        
    tokens.clear();
    blocks.clear();
    is_goto_dst.clear();
    is_fork_origin.clear();
    converge_points = std::map<uint64_t, bool>();
    
    // return function as branch
    uint64_t some_func = function_hashes[std::pair<uint64_t, uint64_t>(l2cagents[character + "_animcmd_effect"], hash40("effect_landinglight", 19))];
    //inst.uc_run_stuff(some_func, true, true, l2cagents[character + "_animcmd_effect"], 0xFFFA000000000000);
    //print_blocks(some_func);
    
    // while loop
    uint64_t while_func = function_hashes[std::pair<uint64_t, uint64_t>(l2cagents[character + "_animcmd_effect"], 0x15a34492fd)];
    //inst.uc_run_stuff(while_func, true, true, l2cagents[character + "_animcmd_effect"], 0xFFFA000000000000);
    //print_blocks(while_func);
    
    // while loop 2
    uint64_t while_func_2 = function_hashes[std::pair<uint64_t, uint64_t>(l2cagents[character + "_animcmd_effect"], 0xa8a5ccccf)];
    //inst.uc_run_stuff(while_func_2, true, true, l2cagents[character + "_animcmd_effect"], 0xFFFA000000000000);
    //print_blocks(while_func_2);
    
    // complicated ifs
    uint64_t some_func2 = function_hashes[std::pair<uint64_t, uint64_t>(l2cagents[character + "_animcmd_sound"], 0x1692b4de28)];
    //inst.uc_run_stuff(some_func2, true, true, l2cagents[character + "_animcmd_sound"], 0xFFFA000000000000);
    //print_blocks(some_func2);
    
    // subroutines w/ ifs
    //inst.uc_run_stuff(0x10011a470, true, true, l2cagent, 0xFFFA000000000000);
    //print_blocks(0x10011a470);
    
    // subroutine immediately following if
    //inst.uc_run_stuff(0x1000f08d0, true, true, l2cagent, 0xFFFA000000000000);
    //print_blocks(0x1000f08d0);
    
    // super stress test; subroutines, splitting
    //inst.uc_run_stuff(0x1000ec3a0, true, true, l2cagent, 0xFFFA000000000000);
    //print_blocks(0x1000ec3a0);
    
    // weird splitting
    //inst.uc_run_stuff(0x1000ece90, true, true, l2cagent, 0xFFFA000000000000);
    //print_blocks(0x1000ece90);

    return 0;
}
