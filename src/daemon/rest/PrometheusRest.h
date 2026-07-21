// src/daemon/rest/PrometheusRest.h
#pragma once

#include <atomic>
#include <map>
#include <memory>
#include <string>

#include <prometheus/family.h>

namespace prometheus
{
	class Counter;
	class Gauge;
	class Registry;
}; // namespace prometheus

//////////////////////////////////////////////////////////////////////////
//                 Registry
//                   _|_
//  CounterFamily-1       CounterFamily-2
//        _|_                   _|_
//  Counter1/Counter2     Counter3/Counter4
//////////////////////////////////////////////////////////////////////////

/// <summary>
/// Metric Wrapper for reg/unreg metric automaticaly
/// </summary>
class CounterMetric
{
public:
	explicit CounterMetric(std::shared_ptr<prometheus::Registry> registry,
						   const std::string &name, const std::string &help,
						   std::map<std::string, std::string> label);

	~CounterMetric();

	prometheus::Counter &metric();

private:
	prometheus::Counter *m_metric;
	prometheus::Family<prometheus::Counter> *m_family;
	std::shared_ptr<prometheus::Registry> m_promRegistry;

	const std::string m_name;
	const std::string m_help;
	const std::map<std::string, std::string> m_label;
};

/// <summary>
/// Metric Wrapper for reg/unreg metric automaticaly
/// </summary>
class GaugeMetric
{
public:
	explicit GaugeMetric(std::shared_ptr<prometheus::Registry> registry,
						 const std::string &name, const std::string &help,
						 std::map<std::string, std::string> label);

	~GaugeMetric();

	prometheus::Gauge &metric();

private:
	prometheus::Gauge *m_metric;
	prometheus::Family<prometheus::Gauge> *m_family;
	std::shared_ptr<prometheus::Registry> m_promRegistry;
	const std::string m_name;
	const std::string m_help;
	const std::map<std::string, std::string> m_label;
};

/// <summary>
/// Prometheus metrics exporter component, owned by RestHandler
/// </summary>
class PrometheusRest
{
public:
	explicit PrometheusRest();
	~PrometheusRest();

	/// <summary>
	/// Create a Counter Metric, the metric unregisters itself from the registry on destruction
	/// </summary>
	/// <param name="metricName"></param>
	/// <param name="metricHelp"></param>
	/// <param name="labels"></param>
	std::shared_ptr<CounterMetric> createPromCounter(const std::string &metricName, const std::string &metricHelp, const std::map<std::string, std::string> &labels);
	/// <summary>
	/// Create a Gauge Metric, the metric unregisters itself from the registry on destruction
	/// </summary>
	/// <param name="metricName"></param>
	/// <param name="metricHelp"></param>
	/// <param name="labels"></param>
	std::shared_ptr<GaugeMetric> createPromGauge(const std::string &metricName, const std::string &metricHelp, const std::map<std::string, std::string> &labels);

	/// <summary>
	/// Collect all metrics
	/// </summary>
	/// <returns></returns>
	std::string collectData();

	/// <summary>
	/// The metrics is collected by Prometheus server or not
	/// </summary>
	/// <returns></returns>
	bool collected();

	/// <summary>
	/// Count one REST request into the HTTP request counters (moved from the former handleRest() override)
	/// </summary>
	/// <param name="method"></param>
	/// <param name="requestUri"></param>
	void countRequest(const std::string &method, const std::string &requestUri);

private:
	/// <summary>
	/// Create metrics
	/// </summary>
	void initMetrics();

private:
	std::atomic_long m_collectTime{0};

	// prometheus registry
	std::shared_ptr<prometheus::Registry> m_promRegistry;

	// prometheus global metric
	std::shared_ptr<CounterMetric> m_scrapeCounter;
	std::shared_ptr<GaugeMetric> m_promGauge;

	// prometheus rest event counter metric
	std::shared_ptr<CounterMetric> m_restGetCounter;
	std::shared_ptr<CounterMetric> m_restPutCounter;
	std::shared_ptr<CounterMetric> m_restDelCounter;
	std::shared_ptr<CounterMetric> m_restPostCounter;
	std::shared_ptr<GaugeMetric> m_appmeshFileDesc;
};

constexpr auto METRIC_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8";
constexpr auto METRIC_PATH = "/metrics";

#define PROM_COUNTER_INCREASE(counter)     \
	{                                      \
		if (counter)                       \
			counter->metric().Increment(); \
	}

// Prometheus scrap counter
#define PROM_METRIC_NAME_appmesh_prom_scrape_count "appmesh_prom_scrape_count"
#define PROM_METRIC_HELP_appmesh_prom_scrape_count "prometheus scrape count"
// App Mesh alive
#define PROM_METRIC_NAME_appmesh_prom_scrape_up "appmesh_prom_scrape_up"
#define PROM_METRIC_HELP_appmesh_prom_scrape_up "prometheus scrape alive"
// App Mesh file descriptors
#define PROM_METRIC_NAME_appmesh_prom_file_descriptor "appmesh_prom_file_descriptor"
#define PROM_METRIC_HELP_appmesh_prom_file_descriptor "appmesh file descriptors"
// App Mesh HTTP request count
#define PROM_METRIC_NAME_appmesh_http_request_count "appmesh_http_request_count"
#define PROM_METRIC_HELP_appmesh_http_request_count "app mesh http request count"
// Application process start count
#define PROM_METRIC_NAME_appmesh_prom_process_start_count "appmesh_prom_process_start_count"
#define PROM_METRIC_HELP_appmesh_prom_process_start_count "application process spawn count"
// Application process id
#define PROM_METRIC_NAME_appmesh_prom_process_id_gauge "appmesh_prom_process_id_gauge"
#define PROM_METRIC_HELP_appmesh_prom_process_id_gauge "application process id"
// Application process memory usage
#define PROM_METRIC_NAME_appmesh_prom_process_memory_gauge "appmesh_prom_process_memory_gauge"
#define PROM_METRIC_HELP_appmesh_prom_process_memory_gauge "application process memory bytes"
// Application process cpu usage
#define PROM_METRIC_NAME_appmesh_prom_process_cpu_gauge "appmesh_prom_process_cpu_gauge"
#define PROM_METRIC_HELP_appmesh_prom_process_cpu_gauge "application process cpu usage"
// Application process file descriptors
#define PROM_METRIC_NAME_appmesh_prom_process_file_descriptors "appmesh_prom_process_file_descriptors"
#define PROM_METRIC_HELP_appmesh_prom_process_file_descriptors "application process file descriptors"
