/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for windows_events
// Spec file: specs/windows/windows_eventlog.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {
namespace table_tests {

class windowsEventLog : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(windowsEventLog, test_sanity) {
  // Query event data for Application channel
  auto const data = execute_query(
      "select * from windows_eventlog where channel = 'Application'");
  ASSERT_GE(data.size(), 0ul);
  ValidationMap row_map = {
      {"channel", NonEmptyString},
      {"datetime", NonEmptyString},
      {"eventid", IntType},
      {"pid", IntType},
      {"tid", IntType},
      {"provider_name", NormalType},
      {"provider_guid", NormalType},
      {"computer_name", NormalType},
      {"task", IntType},
      {"level", IntType},
      {"keywords", NormalType},
      {"data", NormalType},
  };

  validate_rows(data, row_map);

  // max rows tests
  QueryData const r1 = execute_query(
    "select * from windows_eventlog where channel = 'Application' "
    "and max_rows = 15");
  ASSERT_EQ(r1.size(), 15ul);
  QueryData const r2 = execute_query(
    "select * from windows_eventlog where channel = 'Application' "
    "and max_rows = 1");
  ASSERT_EQ(r2.size(), 1ul);
  QueryData const r3 = execute_query(
    "select * from windows_eventlog where channel = 'Application' "
    "and max_rows = 0");
  ASSERT_GT(r3.size(), 0ul);

  // Sequential test: TODO validate
  QueryData const r4 = execute_query(
    "select * from windows_eventlog where channel = 'Application' "
    "and eventid > -1 and max_rows = 5");
  ASSERT_GT(r4.size(), 0ul);
  QueryData const r5 = execute_query(
    "select * from windows_eventlog where channel = 'Application' "
    "and eventid > -1 and max_rows = 5");
  ASSERT_GT(r5.size(), 0ul);
  QueryData const r6 = execute_query(
    "select * from windows_eventlog where channel = 'Application' "
    "and eventid > -1 and max_rows = 5");
  ASSERT_GT(r6.size(), 0ul);
  QueryData const r7 = execute_query(
    "select * from windows_eventlog where channel = 'Application' "
    "and eventid > -1 and max_rows = 5");
  ASSERT_GT(r7.size(), 0ul);
}

} // namespace table_tests
} // namespace osquery
