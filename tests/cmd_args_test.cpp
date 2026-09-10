#include <gtest/gtest.h>
#include "cmd_args.hpp"
#include <vector>
#include <string>

// Helper to convert vector of strings to argc/argv format
class ArgvHelper {
public:
    explicit ArgvHelper(const std::vector<std::string>& args) {
        argv_.reserve(args.size());
        for (const auto& arg : args) {
            argv_.push_back(const_cast<char*>(arg.c_str()));
        }
    }

    [[nodiscard]] int argc() const { return static_cast<int>(argv_.size()); }
    char** argv() { return argv_.data(); }

private:
    std::vector<char*> argv_;
};

TEST(CmdArgsTest, EmptyArgs) {
    std::vector<std::string> args = {"program"};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    EXPECT_FALSE(result.get("nonexistent").has_value());
    EXPECT_TRUE(result.positional.empty());
}

TEST(CmdArgsTest, LongOptionWithValue) {
    std::vector<std::string> args = {"program", "--name", "test"};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_TRUE(result.get("name").has_value());
    EXPECT_EQ(*result.get("name"), "test");
}

TEST(CmdArgsTest, LongOptionWithEquals) {
    std::vector<std::string> args = {"program", "--name=test"};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_TRUE(result.get("name").has_value());
    EXPECT_EQ(*result.get("name"), "test");
}

TEST(CmdArgsTest, LongOptionEmptyValue) {
    std::vector<std::string> args = {"program", "--flag="};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_TRUE(result.get("flag").has_value());
    EXPECT_EQ(*result.get("flag"), "true");
}

TEST(CmdArgsTest, LongOptionWithoutValue) {
    std::vector<std::string> args = {"program", "--flag"};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_TRUE(result.get("flag").has_value());
    EXPECT_EQ(*result.get("flag"), "true");
}

TEST(CmdArgsTest, ShortOptionWithValue) {
    std::vector<std::string> args = {"program", "-n", "test"};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_TRUE(result.get("n").has_value());
    EXPECT_EQ(*result.get("n"), "test");
}

TEST(CmdArgsTest, ShortOptionWithEquals) {
    std::vector<std::string> args = {"program", "-n=test"};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_TRUE(result.get("n").has_value());
    EXPECT_EQ(*result.get("n"), "test");
}

TEST(CmdArgsTest, ShortOptionEmptyValue) {
    std::vector<std::string> args = {"program", "-f="};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_TRUE(result.get("f").has_value());
    EXPECT_EQ(*result.get("f"), "true");
}

TEST(CmdArgsTest, ShortOptionWithoutValue) {
    std::vector<std::string> args = {"program", "-f"};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_TRUE(result.get("f").has_value());
    EXPECT_EQ(*result.get("f"), "true");
}

TEST(CmdArgsTest, GroupedShortOptions) {
    std::vector<std::string> args = {"program", "-abc"};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_TRUE(result.get("a").has_value());
    EXPECT_EQ(*result.get("a"), "true");
    ASSERT_TRUE(result.get("b").has_value());
    EXPECT_EQ(*result.get("b"), "true");
    ASSERT_TRUE(result.get("c").has_value());
    EXPECT_EQ(*result.get("c"), "true");
}

TEST(CmdArgsTest, PositionalArguments) {
    std::vector<std::string> args = {"program", "file1.txt", "file2.txt"};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_EQ(result.positional.size(), 2);
    EXPECT_EQ(result.positional[0], "file1.txt");
    EXPECT_EQ(result.positional[1], "file2.txt");
}

TEST(CmdArgsTest, MixedOptionsAndPositionals) {
    std::vector<std::string> args = {"program", "--name", "test", "file.txt", "-v"};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_TRUE(result.get("name").has_value());
    EXPECT_EQ(*result.get("name"), "test");
    ASSERT_TRUE(result.get("v").has_value());
    EXPECT_EQ(*result.get("v"), "true");
    ASSERT_EQ(result.positional.size(), 1);
    EXPECT_EQ(result.positional[0], "file.txt");
}

TEST(CmdArgsTest, DuplicateKeys) {
    std::vector<std::string> args = {"program", "--name", "first", "--name", "second"};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    // Last value wins
    ASSERT_TRUE(result.get("name").has_value());
    EXPECT_EQ(*result.get("name"), "second");
}

TEST(CmdArgsTest, LongOptionWithSpacedEquals) {
    std::vector<std::string> args = {"program", "--key", "=", "value"};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_TRUE(result.get("key").has_value());
    EXPECT_EQ(*result.get("key"), "value");
}

TEST(CmdArgsTest, ShortOptionWithSpacedEquals) {
    std::vector<std::string> args = {"program", "-k", "=", "value"};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_TRUE(result.get("k").has_value());
    EXPECT_EQ(*result.get("k"), "value");
}

TEST(CmdArgsTest, ValueStartingWithDash) {
    // Value starting with dash should not be treated as option
    std::vector<std::string> args = {"program", "--name", "value", "--other", "-123"};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_TRUE(result.get("name").has_value());
    EXPECT_EQ(*result.get("name"), "value");
    // --other with value starting with dash should be treated as flag
    ASSERT_TRUE(result.get("other").has_value());
    EXPECT_EQ(*result.get("other"), "true");
}

TEST(CmdArgsTest, EmptyStringValue) {
    std::vector<std::string> args = {"program", "--empty", ""};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_TRUE(result.get("empty").has_value());
    EXPECT_EQ(*result.get("empty"), "");
}

TEST(CmdArgsTest, MultipleOptionsAndValues) {
    std::vector<std::string> args = {
        "program",
        "--host", "localhost",
        "--port", "8080",
        "-v",
        "--debug=true",
        "input.txt"
    };
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_TRUE(result.get("host").has_value());
    EXPECT_EQ(*result.get("host"), "localhost");
    ASSERT_TRUE(result.get("port").has_value());
    EXPECT_EQ(*result.get("port"), "8080");
    ASSERT_TRUE(result.get("v").has_value());
    EXPECT_EQ(*result.get("v"), "true");
    ASSERT_TRUE(result.get("debug").has_value());
    EXPECT_EQ(*result.get("debug"), "true");
    ASSERT_EQ(result.positional.size(), 1);
    EXPECT_EQ(result.positional[0], "input.txt");
}

TEST(CmdArgsTest, WhitespaceInValues) {
    std::vector<std::string> args = {"program", "--message", "hello world"};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_TRUE(result.get("message").has_value());
    EXPECT_EQ(*result.get("message"), "hello world");
}

TEST(CmdArgsTest, SpecialCharactersInValues) {
    std::vector<std::string> args = {"program", "--special", "a=b&c"};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_TRUE(result.get("special").has_value());
    EXPECT_EQ(*result.get("special"), "a=b&c");
}

TEST(CmdArgsTest, RealWorldExample_Generate) {
    std::vector<std::string> args = {"jwt++", "--gen", "user", "--pubout"};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_TRUE(result.get("gen").has_value());
    EXPECT_EQ(*result.get("gen"), "user");
    ASSERT_TRUE(result.get("pubout").has_value());
    EXPECT_EQ(*result.get("pubout"), "true");
}

TEST(CmdArgsTest, RealWorldExample_Sign) {
    std::vector<std::string> args = {"jwt++", "--encode", "claims.json", "--inkey", "seed.key"};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_TRUE(result.get("encode").has_value());
    EXPECT_EQ(*result.get("encode"), "claims.json");
    ASSERT_TRUE(result.get("inkey").has_value());
    EXPECT_EQ(*result.get("inkey"), "seed.key");
}

TEST(CmdArgsTest, RealWorldExample_Verify) {
    std::vector<std::string> args = {
        "jwt++",
        "--verify", "token.jwt",
        "--pubin", "pub.key"
    };
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    ASSERT_TRUE(result.get("verify").has_value());
    EXPECT_EQ(*result.get("verify"), "token.jwt");
    ASSERT_TRUE(result.get("pubin").has_value());
    EXPECT_EQ(*result.get("pubin"), "pub.key");
}

TEST(CmdArgsTest, NonexistentOption) {
    std::vector<std::string> args = {"program", "--real", "value"};
    ArgvHelper helper(args);

    auto result = cmd_args::parse(helper.argc(), helper.argv());

    EXPECT_TRUE(result.get("real").has_value());
    EXPECT_FALSE(result.get("fake").has_value());
    EXPECT_FALSE(result.get("").has_value());
}

TEST(CmdArgsTest, ConsistencyBetweenLongAndShortEquals) {
    // Test that --key= and -k= behave consistently (both become "true")
    std::vector<std::string> args1 = {"program", "--longkey="};
    std::vector<std::string> args2 = {"program", "-s="};

    ArgvHelper helper1(args1);
    ArgvHelper helper2(args2);

    auto result1 = cmd_args::parse(helper1.argc(), helper1.argv());
    auto result2 = cmd_args::parse(helper2.argc(), helper2.argv());

    ASSERT_TRUE(result1.get("longkey").has_value());
    EXPECT_EQ(*result1.get("longkey"), "true");

    ASSERT_TRUE(result2.get("s").has_value());
    EXPECT_EQ(*result2.get("s"), "true");
}

