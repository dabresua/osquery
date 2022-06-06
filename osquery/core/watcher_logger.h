/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */
#pragma once

#include <iostream>
#include <sstream>
#include <fstream>
#include <osquery/logger/logger.h>

namespace osquery {

/**
 * @brief Simplistic logger for exporting watchdog logs into a file
 * 
 */
class WatcherLogger {
private:
  std::string buffer;
  std::ofstream file;

public:
  /**
   * @brief Construct a new Watcher Logger object
   * 
   */
  WatcherLogger();

  /**
   * @brief Destructor, saves the buffer into a new line in the file
   * 
   */
  ~WatcherLogger();

  /**
   * @brief Overloaded operator
   * 
   * @tparam T type, must be supported by std::stringstream
   * @param log WatcherLogger object
   * @param val value to log
   * @return WatcherLogger& 
   */
  template<class T>
  WatcherLogger& operator<<(const T &val) {
    std::stringstream ss;
    ss << val;
    buffer += ss.str();
    return *this;
  }

private:
  /**
   * @brief Get the name of the file where log is going to be stored
   * 
   * @return std::string 
   */
  static std::string getFileName();
};

// TODO: variadic macro to add severity
#define WLOG WatcherLogger()

} // namespace osquery
