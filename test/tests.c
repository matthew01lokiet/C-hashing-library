#include <unity.h>
#include "hashing.c"

void setUp()
{
    //Method required. 
}

void tearDown()
{
    //Method required. 
}

void test_circ_right_32bit_8(){
    TEST_ASSERT_EQUAL_HEX32(0xff000000, circ_right_32bit(0x000000ff,8));
}

void test_circ_right_32bit_zero(){
    TEST_ASSERT_EQUAL_HEX32(0x000000ff, circ_right_32bit(0x000000ff,0));
}

void test_circ_right_32bit_full(){
    TEST_ASSERT_EQUAL_HEX32(0x000000ff, circ_right_32bit(0x000000ff,32));
}

void test_circ_right_32bit_48(){
    TEST_ASSERT_EQUAL_HEX32(0x00ff0000, circ_right_32bit(0x000000ff,48));
}

void test_circ_left_32bit_8(){
    TEST_ASSERT_EQUAL_HEX32(0x000000ff, circ_left_32bit(0xff000000,8));
}

void test_circ_left_32bit_zero(){
    TEST_ASSERT_EQUAL_HEX32(0xff000000, circ_left_32bit(0xff000000,0));
}

void test_circ_left_32bit_full(){
    TEST_ASSERT_EQUAL_HEX32(0xff000000, circ_left_32bit(0xff000000,32));
}

void test_circ_left_32bit_48(){
    TEST_ASSERT_EQUAL_HEX32(0x0000ff00, circ_left_32bit(0xff000000,48));
}

void test_sha_224_null_value(){
    TEST_ASSERT_NULL(Hashing.sha_224(NULL,0));
}

void test_sha_224_empty_string(){

    uint8_t test_value[] = {};
    uint32_t expected[] = {
            0xd14a028c,0x2a3a2bc9,0x476102bb,0x288234c4,
            0x15a2b01f,0x828ea62a,0xc5b3e42f
    };
    uint32_t* actual = sha_224(test_value,0);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,7);
    free(actual);
}

void test_sha_224_test_string(){

    uint8_t test_value[] = {'t', 'e', 's', 't'};
    uint32_t expected[] = {
            0x90a3ed9e,0x32b2aaf4,0xc61c410e,0xb9254261,
            0x19e1a9dc,0x53d4286a,0xde99a809
    };
    uint32_t* actual = sha_224(test_value,4);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,7);
    free(actual);
}

void test_sha_224_440_bit_string(){

    const uint8_t msg_size = 55;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0xa91b6f38,0x9fcd14ae,0x3b8bba37,0x17e9cf02,
            0x2a8adbb4,0x1eefacdf,0x556de21f
    };
    uint32_t* actual = sha_224(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,7);
    free(actual);
}

void test_sha_224_448_bit_string(){

    const uint8_t msg_size = 56;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0x7de82550,0xf4c1cb83,0xa31405ec,0xd4ec3e7a,
            0x82a6198b,0xd8da8a60,0x006c2b24
    };
    uint32_t* actual = sha_224(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,7);
    free(actual);
}

void test_sha_224_504_bit_string(){

    const uint8_t msg_size = 63;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0x63194870,0x38b37518,0x59875694,0x8c18cc18,
            0xbeee8a65,0xa32fb9df,0x69495224
    };
    uint32_t* actual = sha_224(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,7);
    free(actual);
}

void test_sha_224_512_bit_string(){

    const uint8_t msg_size = 64;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0xda4b348e,0xbef076f9,0xd8b74dbb,0xb1e3af0a,
            0x4f39f032,0x3a48876f,0xf294f39d
    };
    uint32_t* actual = sha_224(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,7);
    free(actual);
}

void test_sha_224_1600_bit_string(){

    const uint8_t msg_size = 200;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0xc9ce8319,0x943cd1a0,0x7f219eaf,0xe2f9258a,
            0x7d8abc93,0x56214e83,0xcfb85406
    };
    uint32_t* actual = sha_224(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,7);
    free(actual);
}

void test_sha_256_null_value(){
    TEST_ASSERT_NULL(Hashing.sha_256(NULL,0));
}

void test_sha_256_empty_string(){

    uint8_t test_value[] = {};
    uint32_t expected[] = {
            0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924,
            0x27ae41e4, 0x649b934c, 0xa495991b, 0x7852b855
    };
    uint32_t* actual = sha_256(test_value,0);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,8);
    free(actual);
}

void test_sha_256_test_string(){

    uint8_t test_value[] = {'t', 'e', 's', 't'};
    uint32_t expected[] = {
            0x9f86d081, 0x884c7d65, 0x9a2feaa0, 0xc55ad015,
            0xa3bf4f1b, 0x2b0b822c, 0xd15d6c15, 0xb0f00a08
    };
    uint32_t* actual = sha_256(test_value,4);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,8);
    free(actual);
}

void test_sha_256_440_bit_string(){

    const uint8_t msg_size = 55;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0x4c027930, 0x4db390e4, 0x03c91c03, 0x64fd561a,
            0x2f52b087, 0x80a97d52, 0x12ec43f8, 0xd88f73f8
    };
    uint32_t* actual = sha_256(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,8);
    free(actual);
}

void test_sha_256_448_bit_string(){

    const uint8_t msg_size = 56;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0x525ebaf7, 0x58a060b9, 0x0e520c6c, 0x07298df5,
            0xece9aa6b, 0xcf1c0f00, 0x1772c5f2, 0x2db66bd7
    };
    uint32_t* actual = sha_256(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,8);
    free(actual);
}

void test_sha_256_504_bit_string(){

    const uint8_t msg_size = 63;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0xfe60147e, 0xcf5222f9, 0x15ca2c01, 0x25d3d5ad,
            0x3af0a73d, 0x38b5a7b3, 0xf0c8f440, 0x2eade2f3
    };
    uint32_t* actual = sha_256(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,8);
    free(actual);
}

void test_sha_256_512_bit_string(){

    const uint8_t msg_size = 64;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0x3a33722b, 0x9a250ca3, 0xc820f696, 0x045d29ed,
            0x8767dccc, 0x275d1c2a, 0x3e7cc88e, 0x54bcbed1
    };
    uint32_t* actual = sha_256(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,8);
    free(actual);
}

void test_sha_256_1600_bit_string(){

    const uint8_t msg_size = 200;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0x8cbeafc0, 0x5ce09a3e, 0xac73af9f, 0x501dfe20,
            0xdc47081e, 0x87ab7ed0, 0x0a1437c8, 0xbac3f3b5
    };
    uint32_t* actual = sha_256(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,8);
    free(actual);
}

void test_sha_1_null_value(){
    TEST_ASSERT_NULL(Hashing.sha_1(NULL,0));
}

void test_sha_1_empty_string(){

    uint8_t test_value[] = {};
    uint32_t expected[] = {
            0xda39a3ee, 0x5e6b4b0d, 0x3255bfef, 0x95601890, 0xafd80709
    };
    uint32_t* actual = sha_1(test_value,0);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,5);
    free(actual);
}

void test_sha_1_test_string(){

    uint8_t test_value[] = {'t', 'e', 's', 't'};
    uint32_t expected[] = {
            0xa94a8fe5, 0xccb19ba6, 0x1c4c0873, 0xd391e987, 0x982fbbd3
    };
    uint32_t* actual = sha_1(test_value,4);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,5);
    free(actual);
}

void test_sha_1_440_bit_string(){

    const uint8_t msg_size = 55;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0xfec65bc0, 0xaeb97430, 0x8292ccef, 0x3f5e6fde, 0x80643ea1
    };
    uint32_t* actual = sha_1(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,5);
    free(actual);
}

void test_sha_1_448_bit_string(){

    const uint8_t msg_size = 56;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0x4d96fbcf, 0xae99bd32, 0xb90a1da5, 0x90d19a23, 0xdf5d01a1
    };
    uint32_t* actual = sha_1(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,5);
    free(actual);
}

void test_sha_1_504_bit_string(){

    const uint8_t msg_size = 63;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0xceac6782, 0x8f80d1d6, 0x65c6ba56, 0xedc325b5, 0x9ec73ed2
    };
    uint32_t* actual = sha_1(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,5);
    free(actual);
}

void test_sha_1_512_bit_string(){

    const uint8_t msg_size = 64;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0xcb916cf8, 0x97cbc2e1, 0xad7661e8, 0x5066f19b, 0xa81cfb04
    };
    uint32_t* actual = sha_1(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,5);
    free(actual);
}

void test_sha_1_1600_bit_string(){

    const uint8_t msg_size = 200;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0x14c7c303, 0x8cc7deda, 0x52a123c8, 0x14f2ab1f, 0x71b33b0d
    };
    uint32_t* actual = sha_1(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,5);
    free(actual);
}

void test_sha_0_null_value(){
    TEST_ASSERT_NULL(Hashing.sha_0(NULL,0));
}

void test_sha_0_empty_string(){

    uint8_t test_value[] = {};
    uint32_t expected[] = {
            0xf96cea19, 0x8ad1dd56, 0x17ac084a, 0x3d92c610, 0x7708c0ef
    };
    uint32_t* actual = sha_0(test_value,0);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,5);
    free(actual);
}

void test_sha_0_test_string(){

    uint8_t test_value[] = {'t', 'e', 's', 't'};
    uint32_t expected[] = {
            0xf8d3b312, 0x442a6770, 0x6057aeb4, 0x5b983221, 0xafb4f035
    };
    uint32_t* actual = sha_0(test_value,4);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,5);
    free(actual);
}

void test_sha_0_440_bit_string(){

    const uint8_t msg_size = 55;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0x4ce70563, 0x08032cf3, 0x1acee9c1, 0xf0b63e44, 0x3e5d8b39
    };
    uint32_t* actual = sha_0(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,5);
    free(actual);
}

void test_sha_0_448_bit_string(){

    const uint8_t msg_size = 56;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0x049bcf15, 0x4744269a, 0xab489c12, 0x1ddf0cb8, 0x7ed61677
    };
    uint32_t* actual = sha_0(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,5);
    free(actual);
}

void test_sha_0_504_bit_string(){

    const uint8_t msg_size = 63;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0x868d0f6c, 0xc6512d87, 0x26c1bbd4, 0xcdc2d47a, 0xcb8d34b1
    };
    uint32_t* actual = sha_0(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,5);
    free(actual);
}

void test_sha_0_512_bit_string(){

    const uint8_t msg_size = 64;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0x02ddf907, 0xfd8d72dc, 0x1158f9f6, 0xdfefcf7b, 0x73b00f03
    };
    uint32_t* actual = sha_0(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,5);
    free(actual);
}

void test_sha_0_1600_bit_string(){

    const uint8_t msg_size = 200;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0x51703e25, 0x65cc72ea, 0x624366c2, 0x93b1fca2, 0x414ba61a
    };
    uint32_t* actual = sha_0(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,5);
    free(actual);
}

void test_md_5_null_value(){
    TEST_ASSERT_NULL(Hashing.md_5(NULL,0));
}

void test_md_5_empty_string(){

    uint8_t test_value[] = {};
    uint32_t expected[] = {
            0xd41d8cd9, 0x8f00b204, 0xe9800998, 0xecf8427e
    };
    uint32_t* actual = md_5(test_value,0);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,4);
    free(actual);
}

void test_md_5_test_string(){

    uint8_t test_value[] = {'t', 'e', 's', 't'};
    uint32_t expected[] = {
            0x098f6bcd, 0x4621d373, 0xcade4e83, 0x2627b4f6
    };
    uint32_t* actual = md_5(test_value,4);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,4);
    free(actual);
}

void test_md_5_440_bit_string(){

    const uint8_t msg_size = 55;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0x3f6e21c6, 0x2dc1e5ec, 0xca493452, 0xa99aa694
    };
    uint32_t* actual = md_5(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,4);
    free(actual);
}

void test_md_5_448_bit_string(){

    const uint8_t msg_size = 56;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0xc385e3b0, 0x7c1ffaaf, 0xe6d96e49, 0xdf63633e
    };
    uint32_t* actual = md_5(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,4);
    free(actual);
}

void test_md_5_504_bit_string(){

    const uint8_t msg_size = 63;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0x6c8cd692, 0xe405e022, 0xf8b1a105, 0xf787c476
    };
    uint32_t* actual = md_5(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,4);
    free(actual);
}

void test_md_5_512_bit_string(){

    const uint8_t msg_size = 64;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0x2560d0f5, 0xdc4fefaf, 0x2992aa05, 0x2d29404c
    };
    uint32_t* actual = md_5(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,4);
    free(actual);
}

void test_md_5_1600_bit_string(){

    const uint8_t msg_size = 200;

    uint8_t test_value[msg_size];
    for(int i = 0; i < msg_size; i++){
        test_value[i] = 't';
    }
    uint32_t expected[] = {
            0x89ca3202, 0x8ae3bf63, 0x76a6e123, 0xa9c9e41f
    };
    uint32_t* actual = md_5(test_value,msg_size);

    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected,actual,4);
    free(actual);
}

int main(){

    UNITY_BEGIN();

    RUN_TEST(test_circ_right_32bit_8);
    RUN_TEST(test_circ_right_32bit_zero);
    RUN_TEST(test_circ_right_32bit_full);
    RUN_TEST(test_circ_right_32bit_48);

    RUN_TEST(test_circ_left_32bit_8);
    RUN_TEST(test_circ_left_32bit_zero);
    RUN_TEST(test_circ_left_32bit_full);
    RUN_TEST(test_circ_left_32bit_48);

    RUN_TEST(test_sha_224_null_value);
    RUN_TEST(test_sha_224_empty_string);
    RUN_TEST(test_sha_224_test_string);
    RUN_TEST(test_sha_224_440_bit_string);
    RUN_TEST(test_sha_224_448_bit_string);
    RUN_TEST(test_sha_224_504_bit_string);
    RUN_TEST(test_sha_224_512_bit_string);
    RUN_TEST(test_sha_224_1600_bit_string);

    RUN_TEST(test_sha_256_null_value);
    RUN_TEST(test_sha_256_empty_string);
    RUN_TEST(test_sha_256_test_string);
    RUN_TEST(test_sha_256_440_bit_string);
    RUN_TEST(test_sha_256_448_bit_string);
    RUN_TEST(test_sha_256_504_bit_string);
    RUN_TEST(test_sha_256_512_bit_string);
    RUN_TEST(test_sha_256_1600_bit_string);

    RUN_TEST(test_sha_1_null_value);
    RUN_TEST(test_sha_1_empty_string);
    RUN_TEST(test_sha_1_test_string);
    RUN_TEST(test_sha_1_440_bit_string);
    RUN_TEST(test_sha_1_448_bit_string);
    RUN_TEST(test_sha_1_504_bit_string);
    RUN_TEST(test_sha_1_512_bit_string);
    RUN_TEST(test_sha_1_1600_bit_string);

    RUN_TEST(test_sha_0_null_value);
    RUN_TEST(test_sha_0_empty_string);
    RUN_TEST(test_sha_0_test_string);
    RUN_TEST(test_sha_0_440_bit_string);
    RUN_TEST(test_sha_0_448_bit_string);
    RUN_TEST(test_sha_0_504_bit_string);
    RUN_TEST(test_sha_0_512_bit_string);
    RUN_TEST(test_sha_0_1600_bit_string);

    RUN_TEST(test_md_5_null_value);
    RUN_TEST(test_md_5_empty_string);
    RUN_TEST(test_md_5_test_string);
    RUN_TEST(test_md_5_440_bit_string);
    RUN_TEST(test_md_5_448_bit_string);
    RUN_TEST(test_md_5_504_bit_string);
    RUN_TEST(test_md_5_512_bit_string);
    RUN_TEST(test_md_5_1600_bit_string);

    return UNITY_END();
}