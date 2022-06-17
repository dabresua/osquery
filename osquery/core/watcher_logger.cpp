/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/watcher_logger.h>
#include <osquery/core/flags.h>
#include <ctime>
#include <chrono>
#include <filesystem>

namespace osquery {
  CLI_FLAG(string,
           watchdog_logs_path,
           "",
           "Path for saving watchdog logs into");


  WatcherLogger::WatcherLogger() : buffer(), file() {
    file.open(getFileName(), std::ios::out | std::ios::app);
    if (!file.is_open())
      LOG(ERROR) << "can not open the file to write at " 
                 << FLAGS_watchdog_logs_path;
  }

  WatcherLogger::WatcherLogger(const char* file_str, int line_num) 
    : buffer(), file() {
    std::stringstream ss;
    ss << "[" << file_str << ":" << line_num << "] ";
    buffer += ss.str();
    file.open(getFileName(), std::ios::out | std::ios::app);
    if (!file.is_open())
      LOG(ERROR) << "can not open the file to write at " 
                 << FLAGS_watchdog_logs_path;
  }

  WatcherLogger::~WatcherLogger() {
    if (file.is_open()) {
      std::time_t t = std::time(nullptr);
      char tstr[9];
      if (std::strftime(tstr, sizeof(tstr), "%T", std::localtime(&t)))
        file << "[" << tstr << "] ";
      file << buffer << std::endl;
    }
  }

  std::string WatcherLogger::getFileName() {
    std::time_t t = std::time(nullptr);
    char tstr[11];
    if (std::strftime(tstr, sizeof(tstr), "%Y_%m_%d", std::localtime(&t))) {
      std::filesystem::path path(FLAGS_watchdog_logs_path + "/" + tstr + ".wlog");
      return path.make_preferred().string();
      //return FLAGS_watchdog_logs_path + 
      //       std::filesystem::path::preferred_separator + tstr + ".wlog";
    } else {
      std::filesystem::path path(FLAGS_watchdog_logs_path + "/" + "unknown_date.wlog");
      return path.make_preferred().string();
      //return FLAGS_watchdog_logs_path + 
      //      std::filesystem::path::preferred_separator + "unknown_date.wlog";
    }
  }

}