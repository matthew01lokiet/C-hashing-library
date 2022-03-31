#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <byteswap.h>
#include "hashing.h"

static inline uint32_t circ_right_32bit(uint32_t, uint8_t);
static inline uint32_t circ_left_32bit(uint32_t, uint8_t);

/**
 * @brief These constants represent the first 32 bits of the 
 * fractional parts of the cube roots of the first sixty-four
 * prime numbers.
 */
static const uint32_t consts_32_sha[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/**
 * @brief Each of these constants represent the i-th element of the table,
 * which is equal to the integer part of 4294967296 times abs(sin(i)),
 * where i is in radians.
 */
static const uint32_t consts_32_md[] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

/**
 * Computes SHA-224 hash from provided message.
 * @param msg message to hash as byte array
 * @param msg_size number of message bytes
 * @return hash consisting of 7 32-bit words
 */
uint32_t* sha_224(uint8_t* msg,uint64_t msg_size){

    if(!msg){
        return NULL;
    }
    uint64_t numb_of_blocks = (msg_size*8)/512; 
    uint8_t padding_one = 0b10000000;

    if((((msg_size * 8) + 1) % 512) > 448){
        numb_of_blocks += 2;
    } else {
        numb_of_blocks++;
    }

    uint32_t** word_blocks = (uint32_t**)malloc(numb_of_blocks * sizeof(uint32_t*));
    for(uint64_t i = 0; i < numb_of_blocks; i++){
        word_blocks[i] = (uint32_t*)calloc(16,sizeof(uint32_t));
    }

    uint64_t current_block_n = 0;
    uint8_t current_word_n = 0;
    uint64_t message_byte_n = 0;
    for(; current_block_n < numb_of_blocks; current_block_n++){

        for(; current_word_n < 16; current_word_n++){

            for(uint8_t k = 0; k < 4; k++, message_byte_n++){

                if(message_byte_n >= msg_size){
                    goto outside;
                }
                word_blocks[current_block_n][current_word_n] |=
                        ((uint32_t)msg[message_byte_n] << (((message_byte_n%4)-3)*(-1))*8);
            }
        }
        current_word_n = 0;
    }

    outside: word_blocks[current_block_n][current_word_n] |= ((uint32_t)padding_one << (((message_byte_n%4)-3)*(-1))*8);

    word_blocks[numb_of_blocks-1][14] = (uint32_t)((msg_size*8) >> 32);
    word_blocks[numb_of_blocks-1][15] = (uint32_t)(msg_size*8);

    uint32_t* h = (uint32_t*)malloc(8 * sizeof(uint32_t));
    h[0] = 0xc1059ed8;
    h[1] = 0x367cd507;
    h[2] = 0x3070dd17;
    h[3] = 0xf70e5939;
    h[4] = 0xffc00b31;
    h[5] = 0x68581511;
    h[6] = 0x64f98fa7;
    h[7] = 0xbefa4fa4;

    uint32_t reg_a, reg_b, reg_c, reg_d, reg_e, reg_f, reg_g, reg_h;
    uint32_t w[64];
    uint32_t s0, s1, ch, maj;
    uint32_t T1, T2;

    for(int i = 1; i <= numb_of_blocks; i++){

        for(int j = 0; j < 16; j++) {
            w[j] = word_blocks[i-1][j];
        }

        for(int j = 16; j < 64; j++) {

            s0 = circ_right_32bit(w[j-15],7) ^ circ_right_32bit(w[j-15],18) ^ (w[j-15] >> 3);
            s1 = circ_right_32bit(w[j-2],17) ^ circ_right_32bit(w[j-2],19) ^ (w[j-2] >> 10);
            w[j] = w[j-16] + s0 + w[j-7] + s1;
        }

        reg_a = h[0];
        reg_b = h[1];
        reg_c = h[2];
        reg_d = h[3];
        reg_e = h[4];
        reg_f = h[5];
        reg_g = h[6];
        reg_h = h[7];

        for(int j = 0; j < 64; j++) {

            s1 = circ_right_32bit(reg_e,6) ^ circ_right_32bit(reg_e,11) ^ circ_right_32bit(reg_e,25);
            ch = (reg_e & reg_f) ^ ((~reg_e) & reg_g);
            T1 = reg_h + s1 + ch + consts_32_sha[j] + w[j];

            s0 = circ_right_32bit(reg_a,2) ^ circ_right_32bit(reg_a,13) ^ circ_right_32bit(reg_a,22);
            maj = (reg_a & reg_b) ^ (reg_a & reg_c) ^ (reg_b & reg_c);
            T2 = s0 + maj;

            reg_h = reg_g;
            reg_g = reg_f;
            reg_f = reg_e;
            reg_e = reg_d + T1;

            reg_d = reg_c;
            reg_c = reg_b;
            reg_b = reg_a;
            reg_a = T1 + T2;
        }

        h[0] += reg_a;
        h[1] += reg_b;
        h[2] += reg_c;
        h[3] += reg_d;
        h[4] += reg_e;
        h[5] += reg_f;
        h[6] += reg_g;
        h[7] += reg_h;
    }

    for(int i = 0; i < numb_of_blocks; i++) {
        free(word_blocks[i]);
    }
    free(word_blocks);

    return h;
}

/**
 * Computes SHA-256 hash from provided message.
 * @param msg message to hash as byte array
 * @param msg_size number of message bytes
 * @return hash consisting of 8 32-bit words
 */
uint32_t* sha_256(uint8_t* msg,uint64_t msg_size){

    if(!msg){
        return NULL;
    }
    uint64_t numb_of_blocks = (msg_size*8)/512;
    uint8_t padding_one = 0b10000000;

    if((((msg_size * 8) + 1) % 512) > 448){
        numb_of_blocks += 2;
    } else {
        numb_of_blocks++;
    }

    uint32_t** word_blocks = (uint32_t**)malloc(numb_of_blocks * sizeof(uint32_t*));
    for(uint64_t i = 0; i < numb_of_blocks; i++){
        word_blocks[i] = (uint32_t*)calloc(16,sizeof(uint32_t));
    }

    uint64_t current_block_n = 0;
    uint8_t current_word_n = 0;
    uint64_t message_byte_n = 0;
    for(; current_block_n < numb_of_blocks; current_block_n++){

        for(; current_word_n < 16; current_word_n++){

            for(uint8_t k = 0; k < 4; k++, message_byte_n++){

                if(message_byte_n >= msg_size){
                    goto outside;
                }
                word_blocks[current_block_n][current_word_n] |=
                        ((uint32_t)msg[message_byte_n] << (((message_byte_n%4)-3)*(-1))*8);
            }
        }
        current_word_n = 0;
    }

    outside: word_blocks[current_block_n][current_word_n] |= ((uint32_t)padding_one << (((message_byte_n%4)-3)*(-1))*8);

    word_blocks[numb_of_blocks-1][14] = (uint32_t)((msg_size*8) >> 32);
    word_blocks[numb_of_blocks-1][15] = (uint32_t)(msg_size*8);

    uint32_t* h = (uint32_t*)malloc(8 * sizeof(uint32_t));
    h[0] = 0x6a09e667;
    h[1] = 0xbb67ae85;
    h[2] = 0x3c6ef372;
    h[3] = 0xa54ff53a;
    h[4] = 0x510e527f;
    h[5] = 0x9b05688c;
    h[6] = 0x1f83d9ab;
    h[7] = 0x5be0cd19;

    uint32_t reg_a, reg_b, reg_c, reg_d, reg_e, reg_f, reg_g, reg_h;
    uint32_t w[64];
    uint32_t s0, s1, ch, maj;
    uint32_t T1, T2;

    for(int i = 1; i <= numb_of_blocks; i++){

        for(int j = 0; j < 16; j++) {
            w[j] = word_blocks[i-1][j];
        }

        for(int j = 16; j < 64; j++) {

            s0 = circ_right_32bit(w[j-15],7) ^ circ_right_32bit(w[j-15],18) ^ (w[j-15] >> 3);
            s1 = circ_right_32bit(w[j-2],17) ^ circ_right_32bit(w[j-2],19) ^ (w[j-2] >> 10);
            w[j] = w[j-16] + s0 + w[j-7] + s1;
        }

        reg_a = h[0];
        reg_b = h[1];
        reg_c = h[2];
        reg_d = h[3];
        reg_e = h[4];
        reg_f = h[5];
        reg_g = h[6];
        reg_h = h[7];

        for(int j = 0; j < 64; j++) {

            s1 = circ_right_32bit(reg_e,6) ^ circ_right_32bit(reg_e,11) ^ circ_right_32bit(reg_e,25);
            ch = (reg_e & reg_f) ^ ((~reg_e) & reg_g);
            T1 = reg_h + s1 + ch + consts_32_sha[j] + w[j];

            s0 = circ_right_32bit(reg_a,2) ^ circ_right_32bit(reg_a,13) ^ circ_right_32bit(reg_a,22);
            maj = (reg_a & reg_b) ^ (reg_a & reg_c) ^ (reg_b & reg_c);
            T2 = s0 + maj;

            reg_h = reg_g;
            reg_g = reg_f;
            reg_f = reg_e;
            reg_e = reg_d + T1;

            reg_d = reg_c;
            reg_c = reg_b;
            reg_b = reg_a;
            reg_a = T1 + T2;
        }

        h[0] += reg_a;
        h[1] += reg_b;
        h[2] += reg_c;
        h[3] += reg_d;
        h[4] += reg_e;
        h[5] += reg_f;
        h[6] += reg_g;
        h[7] += reg_h;
    }

    for(int i = 0; i < numb_of_blocks; i++) {
        free(word_blocks[i]);
    }
    free(word_blocks);

    return h;
}

#define SHUFFLE_REGISTERS_SHA reg_e = reg_d; \
                              reg_d = reg_c; \
                              reg_c = circ_left_32bit(reg_b, 30); \
                              reg_b = reg_a; \
                              reg_a = temp;
/**
 * Computes SHA-1 hash from provided message.
 * @param msg message to hash as byte array
 * @param msg_size number of message bytes
 * @return hash consisting of 5 32-bit words
 */
uint32_t* sha_1(uint8_t* msg,uint64_t msg_size){

    if(!msg){
        return NULL;
    }
    uint64_t numb_of_blocks = (msg_size*8)/512;
    uint8_t padding_one = 0b10000000;

    if((((msg_size * 8) + 1) % 512) > 448){
        numb_of_blocks += 2;
    } else {
        numb_of_blocks++;
    }

    uint32_t** word_blocks = (uint32_t**)malloc(numb_of_blocks * sizeof(uint32_t*));
    for(uint64_t i = 0; i < numb_of_blocks; i++){
        word_blocks[i] = (uint32_t*)calloc(16,sizeof(uint32_t));
    }

    uint64_t current_block_n = 0;
    uint8_t current_word_n = 0;
    uint64_t message_byte_n = 0;
    for(; current_block_n < numb_of_blocks; current_block_n++){

        for(; current_word_n < 16; current_word_n++){

            for(uint8_t k = 0; k < 4; k++, message_byte_n++){

                if(message_byte_n >= msg_size){
                    goto outside;
                }
                word_blocks[current_block_n][current_word_n] |=
                        ((uint32_t)msg[message_byte_n] << (((message_byte_n%4)-3)*(-1))*8);
            }
        }
        current_word_n = 0;
    }

    outside: word_blocks[current_block_n][current_word_n] |= ((uint32_t)padding_one << (((message_byte_n%4)-3)*(-1))*8);

    word_blocks[numb_of_blocks-1][14] = (uint32_t)((msg_size*8) >> 32);
    word_blocks[numb_of_blocks-1][15] = (uint32_t)(msg_size*8);

    uint32_t* h = (uint32_t*)malloc(5 * sizeof(uint32_t));
    h[0] = 0x67452301;
    h[1] = 0xefcdab89;
    h[2] = 0x98badcfe;
    h[3] = 0x10325476;
    h[4] = 0xc3d2e1f0;

    uint32_t reg_a, reg_b, reg_c, reg_d, reg_e;
    uint32_t w[80];
    uint32_t temp;

    for(int i = 1; i <= numb_of_blocks; i++){

        for(int j = 0; j < 16; j++) {
            w[j] = word_blocks[i-1][j];
        }

        for(int j = 16; j < 80; j++) {
            w[j] = circ_left_32bit((w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16]),1);
        }

        reg_a = h[0];
        reg_b = h[1];
        reg_c = h[2];
        reg_d = h[3];
        reg_e = h[4];

        for(int j = 0; j < 20; j++) {

            temp = circ_left_32bit(reg_a,5) + ((reg_b & reg_c) | ((~reg_b) & reg_d)) + reg_e + 0x5a827999 + w[j];
            SHUFFLE_REGISTERS_SHA
        }

        for(int j = 20; j < 40; j++) {

            temp = circ_left_32bit(reg_a,5) + (reg_b ^ reg_c ^ reg_d) + reg_e + 0x6ed9eba1 + w[j];
            SHUFFLE_REGISTERS_SHA
        }

        for(int j = 40; j < 60; j++) {

            temp = circ_left_32bit(reg_a,5) + ((reg_b & reg_c)|(reg_b & reg_d)|(reg_c & reg_d)) + reg_e + 0x8f1bbcdc
                    + w[j];
            SHUFFLE_REGISTERS_SHA
        }

        for(int j = 60; j < 80; j++) {

            temp = circ_left_32bit(reg_a,5) + (reg_b ^ reg_c ^ reg_d) + reg_e + 0xca62c1d6 + w[j];
            SHUFFLE_REGISTERS_SHA
        }

        h[0] += reg_a;
        h[1] += reg_b;
        h[2] += reg_c;
        h[3] += reg_d;
        h[4] += reg_e;
    }

    for(int i = 0; i < numb_of_blocks; i++) {
        free(word_blocks[i]);
    }
    free(word_blocks);

    return h;
}

/**
 * Computes SHA-0 hash from provided message.
 * @param msg message to hash as byte array
 * @param msg_size number of message bytes
 * @return hash consisting of 5 32-bit words
 */
uint32_t* sha_0(uint8_t* msg,uint64_t msg_size){

    if(!msg){
        return NULL;
    }
    uint64_t numb_of_blocks = (msg_size*8)/512;
    uint8_t padding_one = 0b10000000;

    if((((msg_size * 8) + 1) % 512) > 448){
        numb_of_blocks += 2;
    } else {
        numb_of_blocks++;
    }

    uint32_t** word_blocks = (uint32_t**)malloc(numb_of_blocks * sizeof(uint32_t*));
    for(uint64_t i = 0; i < numb_of_blocks; i++){
        word_blocks[i] = (uint32_t*)calloc(16,sizeof(uint32_t));
    }

    uint64_t current_block_n = 0;
    uint8_t current_word_n = 0;
    uint64_t message_byte_n = 0;
    for(; current_block_n < numb_of_blocks; current_block_n++){

        for(; current_word_n < 16; current_word_n++){

            for(uint8_t k = 0; k < 4; k++, message_byte_n++){

                if(message_byte_n >= msg_size){
                    goto outside;
                }
                word_blocks[current_block_n][current_word_n] |=
                        ((uint32_t)msg[message_byte_n] << (((message_byte_n%4)-3)*(-1))*8);
            }
        }
        current_word_n = 0;
    }

    outside: word_blocks[current_block_n][current_word_n] |= ((uint32_t)padding_one << (((message_byte_n%4)-3)*(-1))*8);

    word_blocks[numb_of_blocks-1][14] = (uint32_t)((msg_size*8) >> 32);
    word_blocks[numb_of_blocks-1][15] = (uint32_t)(msg_size*8);

    uint32_t* h = (uint32_t*)malloc(5 * sizeof(uint32_t));
    h[0] = 0x67452301;
    h[1] = 0xefcdab89;
    h[2] = 0x98badcfe;
    h[3] = 0x10325476;
    h[4] = 0xc3d2e1f0;

    uint32_t reg_a, reg_b, reg_c, reg_d, reg_e;
    uint32_t w[80];
    uint32_t temp;

    for(int i = 1; i <= numb_of_blocks; i++){

        for(int j = 0; j < 16; j++) {
            w[j] = word_blocks[i-1][j];
        }

        for(int j = 16; j < 80; j++) {
            w[j] = (w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16]);
        }

        reg_a = h[0];
        reg_b = h[1];
        reg_c = h[2];
        reg_d = h[3];
        reg_e = h[4];

        for(int j = 0; j < 20; j++) {

            temp = circ_left_32bit(reg_a,5) + ((reg_b & reg_c) | ((~reg_b) & reg_d)) + reg_e + 0x5a827999 + w[j];
            SHUFFLE_REGISTERS_SHA
        }

        for(int j = 20; j < 40; j++) {

            temp = circ_left_32bit(reg_a,5) + (reg_b ^ reg_c ^ reg_d) + reg_e + 0x6ed9eba1 + w[j];
            SHUFFLE_REGISTERS_SHA
        }

        for(int j = 40; j < 60; j++) {

            temp = circ_left_32bit(reg_a,5) + ((reg_b & reg_c)|(reg_b & reg_d)|(reg_c & reg_d)) + reg_e + 0x8f1bbcdc
                   + w[j];
            SHUFFLE_REGISTERS_SHA
        }

        for(int j = 60; j < 80; j++) {

            temp = circ_left_32bit(reg_a,5) + (reg_b ^ reg_c ^ reg_d) + reg_e + 0xca62c1d6 + w[j];
            SHUFFLE_REGISTERS_SHA
        }

        h[0] += reg_a;
        h[1] += reg_b;
        h[2] += reg_c;
        h[3] += reg_d;
        h[4] += reg_e;
    }

    for(int i = 0; i < numb_of_blocks; i++) {
        free(word_blocks[i]);
    }
    free(word_blocks);

    return h;
}

/**
 * Computes MD-5 hash from provided message.
 * @param msg message to hash as byte array
 * @param msg_size number of message bytes
 * @return hash consisting of 4 32-bit words
 */
uint32_t* md_5(uint8_t* msg,uint64_t msg_size){

    if(!msg){
        return NULL;
    }
    uint64_t numb_of_blocks = (msg_size*8)/512;
    uint8_t padding_one = 0b10000000;

    if((((msg_size * 8) + 1) % 512) > 448){
        numb_of_blocks += 2;
    } else {
        numb_of_blocks++;
    }

    uint32_t** word_blocks = (uint32_t**)malloc(numb_of_blocks * sizeof(uint32_t*));
    for(uint64_t i = 0; i < numb_of_blocks; i++){
        word_blocks[i] = (uint32_t*)calloc(16,sizeof(uint32_t));
    }

    uint64_t current_block_n = 0;
    uint8_t current_word_n = 0;
    uint64_t message_byte_n = 0;
    for(; current_block_n < numb_of_blocks; current_block_n++){

        for(; current_word_n < 16; current_word_n++){

            for(uint8_t k = 0; k < 4; k++, message_byte_n++){

                if(message_byte_n >= msg_size){
                    goto outside;
                }
                word_blocks[current_block_n][current_word_n] |=
                        ((uint32_t)msg[message_byte_n] << (message_byte_n%4)*8);
            }
        }
        current_word_n = 0;
    }

    outside: word_blocks[current_block_n][current_word_n] |= ((uint32_t)padding_one << (message_byte_n%4)*8);

    word_blocks[numb_of_blocks-1][14] = (uint32_t)(msg_size*8);
    word_blocks[numb_of_blocks-1][15] = (uint32_t)((msg_size*8) >> 32);

    uint32_t* h = (uint32_t*)malloc(4 * sizeof(uint32_t));
    h[0] = 0x67452301;
    h[1] = 0xefcdab89;
    h[2] = 0x98badcfe;
    h[3] = 0x10325476;

    uint32_t reg_a, reg_b, reg_c, reg_d;
    uint32_t temp1, temp2;

    for(int i = 1; i <= numb_of_blocks; i++){

        reg_a = h[0];
        reg_b = h[1];
        reg_c = h[2];
        reg_d = h[3];

        for(int j = 0; j < 16; j++) {

            temp1 = ( (reg_b & reg_c) | ((~reg_b) & reg_d) );
            temp2 = reg_d;
            reg_d = reg_c;
            reg_c = reg_b;
            switch(j % 4){
                case 0:
                    reg_b += circ_left_32bit(reg_a + temp1 + consts_32_md[j] + word_blocks[i-1][j],7);
                    break;
                case 1:
                    reg_b += circ_left_32bit(reg_a + temp1 + consts_32_md[j] + word_blocks[i-1][j],12);
                    break;
                case 2:
                    reg_b += circ_left_32bit(reg_a + temp1 + consts_32_md[j] + word_blocks[i-1][j],17);
                    break;
                case 3:
                    reg_b += circ_left_32bit(reg_a + temp1 + consts_32_md[j] + word_blocks[i-1][j],22);
                    break;
            }
            reg_a = temp2;
        }

        for(int j = 16; j < 32; j++) {

            temp1 = ((reg_d&reg_b)|((~reg_d)&reg_c));
            temp2 = reg_d;
            reg_d = reg_c;
            reg_c = reg_b;
            switch(j % 4){
                case 0:
                    reg_b += circ_left_32bit(reg_a + temp1 + consts_32_md[j] + word_blocks[i-1][(5*j + 1)%16],5);
                    break;
                case 1:
                    reg_b += circ_left_32bit(reg_a + temp1 + consts_32_md[j] + word_blocks[i-1][(5*j + 1)%16],9);
                    break;
                case 2:
                    reg_b += circ_left_32bit(reg_a + temp1 + consts_32_md[j] + word_blocks[i-1][(5*j + 1)%16],14);
                    break;
                case 3:
                    reg_b += circ_left_32bit(reg_a + temp1 + consts_32_md[j] + word_blocks[i-1][(5*j + 1)%16],20);
                    break;
            }
            reg_a = temp2;
        }

        for(int j = 32; j < 48; j++) {

            temp1 = ((reg_b^reg_c)^reg_d);
            temp2 = reg_d;
            reg_d = reg_c;
            reg_c = reg_b;
            switch(j % 4){
                case 0:
                    reg_b += circ_left_32bit(reg_a + temp1 + consts_32_md[j] + word_blocks[i-1][(3*j + 5)%16],4);
                    break;
                case 1:
                    reg_b += circ_left_32bit(reg_a + temp1 + consts_32_md[j] + word_blocks[i-1][(3*j + 5)%16],11);
                    break;
                case 2:
                    reg_b += circ_left_32bit(reg_a + temp1 + consts_32_md[j] + word_blocks[i-1][(3*j + 5)%16],16);
                    break;
                case 3:
                    reg_b += circ_left_32bit(reg_a + temp1 + consts_32_md[j] + word_blocks[i-1][(3*j + 5)%16],23);
                    break;
            }
            reg_a = temp2;
        }

        for(int j = 48; j < 64; j++) {

            temp1 = (reg_c^(reg_b|(~reg_d)));
            temp2 = reg_d;
            reg_d = reg_c;
            reg_c = reg_b;
            switch(j % 4){
                case 0:
                    reg_b += circ_left_32bit(reg_a + temp1 + consts_32_md[j] + word_blocks[i-1][(7*j)%16],6);
                    break;
                case 1:
                    reg_b += circ_left_32bit(reg_a + temp1 + consts_32_md[j] + word_blocks[i-1][(7*j)%16],10);
                    break;
                case 2:
                    reg_b += circ_left_32bit(reg_a + temp1 + consts_32_md[j] + word_blocks[i-1][(7*j)%16],15);
                    break;
                case 3:
                    reg_b += circ_left_32bit(reg_a + temp1 + consts_32_md[j] + word_blocks[i-1][(7*j)%16],21);
                    break;
            }
            reg_a = temp2;
        }

        h[0] += reg_a;
        h[1] += reg_b;
        h[2] += reg_c;
        h[3] += reg_d;
    }

    h[0] = __bswap_32(h[0]);
    h[1] = __bswap_32(h[1]);
    h[2] = __bswap_32(h[2]);
    h[3] = __bswap_32(h[3]);

    for(int i = 0; i < numb_of_blocks; i++) {
        free(word_blocks[i]);
    }
    free(word_blocks);

    return h;
}

/**
 * Computes MD-4 hash from provided message.
 * @param msg message to hash as byte array
 * @param msg_size number of message bytes
 * @return hash consisting of 4 32-bit words
 */
uint32_t* md_4(uint8_t* msg,uint64_t msg_size){

    if(!msg){
        return NULL;
    }
    uint64_t numb_of_blocks = (msg_size*8)/512;
    uint8_t padding_one = 0b10000000;

    if((((msg_size * 8) + 1) % 512) > 448){
        numb_of_blocks += 2;
    } else {
        numb_of_blocks++;
    }

    uint32_t** word_blocks = (uint32_t**)malloc(numb_of_blocks * sizeof(uint32_t*));
    for(uint64_t i = 0; i < numb_of_blocks; i++){
        word_blocks[i] = (uint32_t*)calloc(16,sizeof(uint32_t));
    }

    uint64_t current_block_n = 0;
    uint8_t current_word_n = 0;
    uint64_t message_byte_n = 0;
    for(; current_block_n < numb_of_blocks; current_block_n++){

        for(; current_word_n < 16; current_word_n++){

            for(uint8_t k = 0; k < 4; k++, message_byte_n++){

                if(message_byte_n >= msg_size){
                    goto outside;
                }
                word_blocks[current_block_n][current_word_n] |=
                        ((uint32_t)msg[message_byte_n] << (message_byte_n%4)*8);
            }
        }
        current_word_n = 0;
    }

    outside: word_blocks[current_block_n][current_word_n] |= ((uint32_t)padding_one << (message_byte_n%4)*8);

    word_blocks[numb_of_blocks-1][14] = (uint32_t)(msg_size*8);
    word_blocks[numb_of_blocks-1][15] = (uint32_t)((msg_size*8) >> 32);

    uint32_t* h = (uint32_t*)malloc(4 * sizeof(uint32_t));
    h[0] = 0x67452301;
    h[1] = 0xefcdab89;
    h[2] = 0x98badcfe;
    h[3] = 0x10325476;

    uint32_t reg_a, reg_b, reg_c, reg_d;
    uint32_t temp1, temp2;
    uint8_t p[] = {0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15};

    for(int i = 1; i <= numb_of_blocks; i++){

        reg_a = h[0];
        reg_b = h[1];
        reg_c = h[2];
        reg_d = h[3];

        for(int j = 0; j < 16; j++) {

            temp1 = ((reg_b&reg_c)|((~reg_b)&reg_d));
            temp2 = reg_d;
            reg_d = reg_c;
            reg_c = reg_b;
            switch(j % 4){
                case 0:
                    reg_b = circ_left_32bit(reg_a + temp1 + word_blocks[i-1][j],3);
                    break;
                case 1:
                    reg_b = circ_left_32bit(reg_a + temp1 + word_blocks[i-1][j],7);
                    break;
                case 2:
                    reg_b = circ_left_32bit(reg_a + temp1 + word_blocks[i-1][j],11);
                    break;
                case 3:
                    reg_b = circ_left_32bit(reg_a + temp1 + word_blocks[i-1][j],19);
                    break;
            }
            reg_a = temp2;
        }

        for(int j = 16; j < 32; j++) {

            temp1 = ((reg_b&reg_c)|(reg_b&reg_d)|(reg_c&reg_d));
            temp2 = reg_d;
            reg_d = reg_c;
            reg_c = reg_b;
            switch(j % 4){
                case 0:
                    reg_b = circ_left_32bit(reg_a + temp1 + 0x5a827999 + word_blocks[i-1][(j%16)/4],3);
                    break;
                case 1:
                    reg_b = circ_left_32bit(reg_a + temp1 + 0x5a827999 + word_blocks[i-1][(j%16)/4 + 4],5);
                    break;
                case 2:
                    reg_b = circ_left_32bit(reg_a + temp1 + 0x5a827999 + word_blocks[i-1][(j%16)/4 + 8],9);
                    break;
                case 3:
                    reg_b = circ_left_32bit(reg_a + temp1 + 0x5a827999 + word_blocks[i-1][(j%16)/4 + 12],13);
                    break;
            }
            reg_a = temp2;
        }

        for(int j = 32; j < 48; j++) {

            temp1 = ((reg_b^reg_c)^reg_d);
            temp2 = reg_d;
            reg_d = reg_c;
            reg_c = reg_b;
            switch(j % 4){
                case 0:
                    reg_b = circ_left_32bit(reg_a + temp1 + 0x6ed9eba1 + word_blocks[i-1][p[j%16]],3);
                    break;
                case 1:
                    reg_b = circ_left_32bit(reg_a + temp1 + 0x6ed9eba1 + word_blocks[i-1][p[j%16]],9);
                    break;
                case 2:
                    reg_b = circ_left_32bit(reg_a + temp1 + 0x6ed9eba1 + word_blocks[i-1][p[j%16]],11);
                    break;
                case 3:
                    reg_b = circ_left_32bit(reg_a + temp1 + 0x6ed9eba1 + word_blocks[i-1][p[j%16]],15);
                    break;
            }
            reg_a = temp2;
        }

        h[0] += reg_a;
        h[1] += reg_b;
        h[2] += reg_c;
        h[3] += reg_d;
    }

    h[0] = __bswap_32(h[0]);
    h[1] = __bswap_32(h[1]);
    h[2] = __bswap_32(h[2]);
    h[3] = __bswap_32(h[3]);

    for(int i = 0; i < numb_of_blocks; i++) {
        free(word_blocks[i]);
    }
    free(word_blocks);

    return h;
}

/**
 * Returns new message after ROT-13 rotation.
 * @param msg message to rotate as byte array (ascii)
 * @param msg_size number of message bytes
 * @return new message after rotation as byte array
 */
uint8_t* rot_13(uint8_t* msg, uint64_t msg_size){

    if(!msg){
        return NULL;
    }

    uint8_t* rot_msg = malloc(msg_size * sizeof(msg[0]));

    for(uint64_t i = 0; i < msg_size; i++){

        if('a' <= msg[i] && msg[i] <= 'z'){

            if((rot_msg[i] = msg[i] + 13) > 122){
                rot_msg[i] = 96 + (rot_msg[i]-122);
            }
        } else if('A' <= msg[i] && msg[i] <= 'Z') {

            if((rot_msg[i] = msg[i] + 13) > 90){
                rot_msg[i] = 64 + (rot_msg[i]-90);
            }
        } else {

            free(rot_msg);
            return NULL;
        }
    }

    return rot_msg;
}

// HELPER METHODS
static inline uint32_t circ_right_32bit(uint32_t num, uint8_t shift_num){
    const unsigned int mask = CHAR_BIT * sizeof(num) - 1;
    shift_num &= mask;
    return (num >> shift_num) | (num << (-shift_num & mask));
}

static inline uint32_t circ_left_32bit(uint32_t num, uint8_t shift_num){
    const unsigned int mask = CHAR_BIT * sizeof(num) - 1;
    shift_num &= mask;
    return (num << shift_num) | (num >> (-shift_num & mask));
}

// INTERFACE
const struct hashing Hashing = {
    .sha_224 = sha_224,
    .sha_256 = sha_256,
    .sha_0 = sha_0,
    .sha_1 = sha_1,
    .md_4 = md_4,
    .md_5 = md_5,
    .rot_13 = rot_13
};