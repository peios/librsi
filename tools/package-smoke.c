/* Compile and link smoke test for the installed librsi development surface. */
#include <rsi.h>

static int (*volatile entry)(const struct rsi_hive *, uint32_t, uint64_t);

int main(void)
{
	entry = rsi_register;
	return entry == 0;
}
