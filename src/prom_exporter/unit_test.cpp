#include <cstdio>
#include <iostream>
#include "counter.h"
#include "registry.h"
#include <serializer.h>
#include <text_serializer.h>
#include <histogram.h>

using namespace prometheus;
///////////////////////////////////////////////////////
// From github:
// https://github.com/jupp0r/prometheus-cpp
///////////////////////////////////////////////////////
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




	std::cout << "############################" << std::endl;

	Registry registry;
	auto& counter_family = BuildCounter().Name("test").Help("a test").Register(registry);
	counter_family.Add({ {"name", "counter1"} });
	counter_family.Add({ {"name", "counter2"} });

	auto& histogram_family =
		BuildHistogram().Name("hist").Help("Test Histogram").Register(registry);
	auto& histogram = histogram_family.Add({ {"name", "test_histogram_1"} },
		Histogram::BucketBoundaries{ 0, 1, 2 });
	histogram.Observe(1.1);
	auto collected = registry.Collect();

	auto serializer = std::unique_ptr<Serializer>(new TextSerializer());
	auto msg = serializer->Serialize(collected);
	std::cout << msg << std::endl;
	getchar();
	return 0;
}

/*
counter.Value() = 7.000000
gauge.Value() = 0.000000
############################
# HELP test a test
# TYPE test counter
test{name="counter2"} 0.000000
test{name="counter1"} 0.000000
# HELP hist Test Histogram
# TYPE hist histogram
hist_count{name="test_histogram_1"} 1
hist_sum{name="test_histogram_1"} 1.100000
hist_bucket{name="test_histogram_1",le="0.000000"} 0
hist_bucket{name="test_histogram_1",le="1.000000"} 0
hist_bucket{name="test_histogram_1",le="2.000000"} 1
hist_bucket{name="test_histogram_1",le="+Inf"} 1
*/