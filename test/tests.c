#include <gtest/gtest.h>

int add(int a1, int a2)
{
	return a1 + a2;
}

TEST(Example, addNum)
{
	EXPECT_EQ(2, add(1,1));
}

int main(int argc, char **argv)
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

