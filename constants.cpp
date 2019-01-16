#include "constants.h"

std::set<uint32_t> last_crcs;
std::map<uint64_t, std::string> unhash;
std::map<uint32_t, std::string> unhash_parts;
std::map<uint64_t, std::string> status_funcs;

std::map<std::string, std::vector<std::string> > character_objects;

std::string agents[11] = { "status_script", "animcmd_effect", "animcmd_effect_share", "animcmd_expression", "animcmd_expression_share", "animcmd_game", "animcmd_game_share", "animcmd_sound", "animcmd_sound_share", "ai_action", "ai_mode" };

std::string characters[89] = {
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

std::string status_func[23] = {
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

std::string fighter_status_kind[0x1A7] = {
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
