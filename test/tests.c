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

int main(){

    UNITY_BEGIN();

    RUN_TEST(test_circ_right_32bit_8);
    RUN_TEST(test_circ_right_32bit_zero);
    RUN_TEST(test_circ_right_32bit_full);
    RUN_TEST(test_circ_right_32bit_48);

    RUN_TEST(test_sha_224_null_value);
    RUN_TEST(test_sha_224_empty_string);
    RUN_TEST(test_sha_224_test_string);
    RUN_TEST(test_sha_224_440_bit_string);
    RUN_TEST(test_sha_224_448_bit_string);
    RUN_TEST(test_sha_224_504_bit_string);
    RUN_TEST(test_sha_224_512_bit_string);
    RUN_TEST(test_sha_224_1600_bit_string);

    return UNITY_END();
}