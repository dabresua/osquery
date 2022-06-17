/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/core/watcher_logger.h>
#include <osquery/tests/test_util.h>
#include <osquery/core/flags.h>

#include <filesystem>
#include <iostream>

using namespace testing;

namespace osquery {

class WatcherLoggerTests : public testing::Test {
  protected:
    WatcherLoggerTests() {
      std::filesystem::path cwd = std::filesystem::current_path();
      Flag::updateValue("watchdog_logs_path", cwd.string());
      EXPECT_EQ(Flag::getValue("watchdog_logs_path"), cwd);
    }
  
  public:
  static std::string getFileName() {
    std::time_t t = std::time(nullptr);
    char tstr[11];
    std::string fstr = Flag::getValue("watchdog_logs_path");
    if (std::strftime(tstr, sizeof(tstr), "%Y_%m_%d", std::localtime(&t))) {
      std::filesystem::path path(fstr + "/" + tstr + ".wlog");
      return path.make_preferred().string();
    } else {
      std::filesystem::path path(fstr + "/" + "unknown_date.wlog");
      return path.make_preferred().string();
    }
  }

  static void check(std::ifstream &file, const std::vector<std::string> &tv) {
    // Open the file, read and compare
    file.open(getFileName());
    EXPECT_TRUE(file.is_open());
    std::cout << "File ----------------------" << std::endl;
    unsigned int i = 0;
    std::string line;
    while (std::getline(file, line)) {
      std::cout << line << std::endl;
      std::string str = tv[i];
      i++;

      EXPECT_EQ(line, str);
    }
    file.close();
    std::cout << "File ----------------------" << std::endl;
  }
};

TEST_F(WatcherLoggerTests, test_logging) {
  std::filesystem::remove(WatcherLoggerTests::getFileName());
  std::string str = "a string", str2 = "another sting";
  std::vector<std::string> tv;
  int num = 123456, num2 = 789012;
  std::ifstream file;

  std::time_t t = std::time(nullptr);
  char tstr[9];
  std::strftime(tstr, sizeof(tstr), "%T", std::localtime(&t));
  std::stringstream ss;

  {
    WLOG << str;
    WLOG << num;
    ss << "[" << tstr << "] " << str;
    tv.push_back(ss.str());
    ss.str("");
    ss << "[" << tstr << "] " << num;
    tv.push_back(ss.str());
    ss.str("");
  }
  WatcherLoggerTests::check(file, tv);

  {
    WLOG << str2 << " " << num2;
    ss << "[" << tstr << "] " << str2 << " " << num2;
    tv.push_back(ss.str());
    ss.str("");
  }
  WatcherLoggerTests::check(file, tv);

  {
    WFLOG << str; // Do not move this line (97)
    WFLOG << num; // Do not move this line (98)
    ss << "[" << tstr << "] [" << __FILE__ << ":" << 97 << "] " << str;
    tv.push_back(ss.str());
    ss.str("");
    ss << "[" << tstr << "] [" << __FILE__ << ":" << 98 << "] " << num;
    tv.push_back(ss.str());
    ss.str("");
  }
  WatcherLoggerTests::check(file, tv);
}

} // namespace osquery