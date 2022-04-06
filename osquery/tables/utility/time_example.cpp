#include <ctime>
#include <osquery/core/tables.h>

namespace osquery {
namespace tables {

QueryData genTimeExample(QueryContext &context) {
	QueryData rows;

	Row r;

	time_t tmp_time = time(0);
	struct tm* now = localtime(&tmp_time);

	r["hour"]    = INTEGER(now->tm_hour);
	r["minutes"] = INTEGER(now->tm_min);
	r["seconds"] = INTEGER(now->tm_sec);

	rows.push_back(std::move(r));
	return rows;
}
} // tables
} // osquery