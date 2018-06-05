#include <gtest/gtest.h>

extern int add(int a, int b);

TEST(testCase, test)
{
	EXPECT_EQ(add(2, 3), 5);
}

int main(int argc, char **argv)
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
