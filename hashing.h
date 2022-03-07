#pragma once

struct hashing {
    const char* (*sha_224)(const char*);
    const char* (*sha_256)(const char*);
    const char* (*sha_384)(const char*);
    const char* (*sha_512)(const char*);
    const char* (*sha_0)(const char*);
    const char* (*sha_1)(const char*);
    const char* (*md_4)(const char*);
    const char* (*md_5)(const char*);
    const char* (*rot_13)(const char*);
};

extern const struct hashing Hashing;