#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/info/platform_type.h>

namespace osquery{
namespace table_tests {

class TimeExample : public testing::Test {
	protected:
	void SetUp() override {
		setUpEnvironment();
	}
};

TEST_F(TimeExample, test_sanity) {
	QueryData data = execute_query("select * from time_example");

	ASSERT_EQ(data.size(), 1ul);

	ValidationMap row_map = {
		{"hour", IntMinMaxCheck(0, 24)},
		{"minutes", IntMinMaxCheck(0, 59)},
		{"seconds", IntMinMaxCheck(0, 59)},
	};

	validate_rows(data, row_map);
}

}
} // osquery