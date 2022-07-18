/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/core/core.h>
#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

/**
 * @brief defines the structure that saves current status for sequential
 *        extraction. Applies to a channel.
 * 
 */
struct SequentialItem {
  std::string datetime; /**< timestamp of last event, used as a pointer */

  SequentialItem() : datetime() {}

  /**
   * @brief load values from database in case there are stored
   * @param queryContext context of the query 
   * 
   */
  void load(QueryContext& queryContext);

  /**
   * @brief saves values into database
   * @param QueryContext context of the query 
   */
  void save(QueryContext& queryContext);
};

/*
 * @brief Helper function to parse the xml event string
 *
 * @param context the query context
 * @param xml_event the windows events rendered in xml format
 * @param row the table row generated from the event string
 * @param seqItem for saving status between queries
 * @param maxRows the maximum number of rows is able to return
 *
 * This function takes the windows events rendered in xml format and
 * generates the table row for the query.
 */
Status parseWelXml(QueryContext& context, std::wstring& xml_event, Row& row, 
                   SequentialItem& seqItem, int maxRows);

/*
 * @brief Helper function to generate the xfilter string from constraints
 *
 * @param context the query context for generating the xfilter string
 * @param xfilter a filtering string that can be used with EvtQuery
 *
 * This function takes the query context generate the xfilter string from
 * provided constraints that can be used to selectively filter the queried
 * events.
 */
void genXfilterFromConstraints(QueryContext& context, std::string& xfilter, 
                               SequentialItem& seqItem);

} // namespace tables
} // namespace osquery
