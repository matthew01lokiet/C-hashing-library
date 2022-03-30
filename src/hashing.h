#include <stdint.h>
#pragma once

struct hashing {
    uint32_t* (*sha_256)(uint8_t*,uint64_t);
    uint32_t* (*sha_224)(uint8_t*,uint64_t);
    uint32_t* (*sha_1)(uint8_t*,uint64_t);
    uint32_t* (*sha_0)(uint8_t*,uint64_t);
    uint32_t* (*md_5)(uint8_t*,uint64_t);
    uint32_t* (*md_4)(uint8_t*,uint64_t);
    uint8_t* (*rot_13)(uint8_t*,uint64_t);
};

extern const struct hashing Hashing;