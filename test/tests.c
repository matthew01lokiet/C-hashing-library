#include <unity.h>
#include <hashing.h>

void setUp()
{
    //Method required. 
}

void tearDown()
{
    //Method required. 
}

void test_sha_256_null_value(){
    TEST_ASSERT_NULL(Hashing.sha_256(NULL));
}

void test_sha_224_null_value(){
    TEST_ASSERT_NULL(Hashing.sha_224(NULL));
}

void test_sha_1_null_value(){
    TEST_ASSERT_NULL(Hashing.sha_1(NULL));
}

void test_sha_0_null_value(){
    TEST_ASSERT_NULL(Hashing.sha_0(NULL));
}

void test_md_4_null_value(){
    TEST_ASSERT_NULL(Hashing.md_4(NULL));
}

void test_md_5_null_value(){
    TEST_ASSERT_NULL(Hashing.md_5(NULL));
}

void test_rot_13_null_value(){
    TEST_ASSERT_NULL(Hashing.rot_13(NULL));
}

int main(){

    UNITY_BEGIN();

    RUN_TEST(test_sha_256_null_value);
    RUN_TEST(test_sha_224_null_value);
    RUN_TEST(test_sha_1_null_value);
    RUN_TEST(test_sha_0_null_value);
    RUN_TEST(test_md_4_null_value);
    RUN_TEST(test_md_5_null_value);
    RUN_TEST(test_rot_13_null_value);

    return UNITY_END();
}