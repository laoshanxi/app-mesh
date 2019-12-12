#include <cstdio>

#include "counter.h"
#include "registry.h"

using namespace prometheus;

int main()
{
	Counter counter;
	counter.Increment();
	counter.Increment();
	counter.Increment(5);
	counter.Increment(-5.0);

    printf("counter.Value() = %f \n", counter.Value());


	Gauge gauge;
	gauge.Set(3.0);
	gauge.Set(8.0);
	gauge.Increment(5.0);
	gauge.Set(1.0);
	gauge.Decrement(1.0);
	//gauge.SetToCurrentTime();
	printf("gauge.Value() = %f \n", gauge.Value());


	Registry registry{};
	auto& counter_family =
		BuildCounter().Name("test").Help("a test").Register(registry);
	counter_family.Add({ {"name", "counter1"} });
	counter_family.Add({ {"name", "counter2"} });
	auto collected = registry.Collect();

	getchar();
    return 0;
}