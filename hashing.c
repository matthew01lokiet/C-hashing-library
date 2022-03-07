#include "hashing.h"

const char* sha_224(const char* text){
    return text;
}

const char* sha_256(const char* text){
    return text;
}

const char* sha_384(const char* text){
    return text;
}

const char* sha_512(const char* text){
    return text;
}

const char* sha_0(const char* text){
    return text;
}

const char* sha_1(const char* text){
    return text;
}

const char* md_4(const char* text){
    return text;
}

const char* md_5(const char* text){
    return text;
}

const char* rot_13(const char* text){
    return text;
}

//------------------------------------

const struct hashing Hashing = {
    .sha_224 = sha_224,
    .sha_256 = sha_256,
    .sha_384 = sha_384,
    .sha_512 = sha_512,
    .sha_0 = sha_0,
    .sha_1 = sha_1,
    .md_4 = md_4,
    .md_5 = md_5,
    .rot_13 = rot_13
};