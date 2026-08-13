// src/daemon/rest/PrometheusRest.h
#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <prometheus/family.h>

namespace prometheus
{
	class Counter;
	class Gauge;
	class Histogram;
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
						   prometheus::Family<prometheus::Counter> &family, const std::string &name,
						   std::map<std::string, std::string> label);

	~CounterMetric();

	prometheus::Counter &metric();

private:
	prometheus::Counter *m_metric;
	prometheus::Family<prometheus::Counter> *m_family;
	std::shared_ptr<prometheus::Registry> m_promRegistry;

	const std::string m_name;
};

/// <summary>
/// Metric Wrapper for reg/unreg metric automaticaly
/// </summary>
class GaugeMetric
{
public:
	explicit GaugeMetric(std::shared_ptr<prometheus::Registry> registry,
						 prometheus::Family<prometheus::Gauge> &family, const std::string &name,
						 std::map<std::string, std::string> label);

	~GaugeMetric();

	prometheus::Gauge &metric();

private:
	prometheus::Gauge *m_metric;
	prometheus::Family<prometheus::Gauge> *m_family;
	std::shared_ptr<prometheus::Registry> m_promRegistry;
	const std::string m_name;
};

class HistogramMetric
{
public:
	explicit HistogramMetric(std::shared_ptr<prometheus::Registry> registry,
							 prometheus::Family<prometheus::Histogram> &family, const std::string &name,
							 std::map<std::string, std::string> label, const std::vector<double> &buckets);
	~HistogramMetric();
	prometheus::Histogram &metric();

private:
	prometheus::Histogram *m_metric;
	prometheus::Family<prometheus::Histogram> *m_family;
	std::shared_ptr<prometheus::Registry> m_promRegistry;
	const std::string m_name;
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
	std::shared_ptr<HistogramMetric> createPromHistogram(const std::string &metricName, const std::string &metricHelp,
		const std::map<std::string, std::string> &labels, const std::vector<double> &buckets);
	/// <summary>
	/// Collect all metrics
	/// </summary>
	/// <returns></returns>
	std::string collectData();
	void refreshProcessMetrics(void *processSnapshot);

	uint64_t scrapeGeneration() const;

	// HTTP RED lifecycle. route must already be normalized and bounded.
	void httpRequestStarted(const std::string &method, const std::string &route);
	void httpRequestFinished(const std::string &method, const std::string &route, int statusCode, double durationSeconds);

private:
	/// <summary>
	/// Create metrics
	/// </summary>
	void initMetrics();

private:
	std::atomic<uint64_t> m_scrapeGeneration{0};

	// prometheus registry
	std::shared_ptr<prometheus::Registry> m_promRegistry;
	std::mutex m_familyMutex;
	std::map<std::string, prometheus::Family<prometheus::Counter> *> m_counterFamilies;
	std::map<std::string, prometheus::Family<prometheus::Gauge> *> m_gaugeFamilies;
	std::map<std::string, prometheus::Family<prometheus::Histogram> *> m_histogramFamilies;

	std::mutex m_httpMetricMutex;
	std::map<std::string, std::shared_ptr<CounterMetric>> m_httpRequestCounters;
	std::map<std::string, std::shared_ptr<GaugeMetric>> m_httpInflightGauges;
	std::map<std::string, std::shared_ptr<HistogramMetric>> m_httpDurationHistograms;
	// prometheus global metric
	std::shared_ptr<CounterMetric> m_scrapeCounter;
	std::shared_ptr<CounterMetric> m_collectionErrorCounter;
	std::shared_ptr<GaugeMetric> m_appmeshPid;
	std::shared_ptr<GaugeMetric> m_buildInfo;

	std::shared_ptr<GaugeMetric> m_appmeshFileDesc;
};

constexpr auto METRIC_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8";
constexpr auto METRIC_PATH = "/metrics";
constexpr auto METRIC_APP_PATH = "/appmesh/metrics";

constexpr auto PROM_METRIC_NAME_appmesh_metrics_scrapes_total = "appmesh_metrics_scrapes_total";
constexpr auto PROM_METRIC_HELP_appmesh_metrics_scrapes_total = "Total number of App Mesh metrics scrapes";
constexpr auto PROM_METRIC_NAME_appmesh_metrics_collection_errors_total = "appmesh_metrics_collection_errors_total";
constexpr auto PROM_METRIC_HELP_appmesh_metrics_collection_errors_total = "Total number of App Mesh metrics collection errors";
constexpr auto PROM_METRIC_NAME_appmesh_process_open_fds = "appmesh_process_open_fds";
constexpr auto PROM_METRIC_HELP_appmesh_process_open_fds = "Open file descriptors in the App Mesh daemon process tree";
constexpr auto PROM_METRIC_NAME_appmesh_process_id = "appmesh_process_id";
constexpr auto PROM_METRIC_HELP_appmesh_process_id = "App Mesh daemon process ID";
constexpr auto PROM_METRIC_NAME_appmesh_http_requests_total = "appmesh_http_requests_total";
constexpr auto PROM_METRIC_HELP_appmesh_http_requests_total = "Total number of App Mesh HTTP requests";
constexpr auto PROM_METRIC_NAME_appmesh_http_request_duration_seconds = "appmesh_http_request_duration_seconds";
constexpr auto PROM_METRIC_HELP_appmesh_http_request_duration_seconds = "App Mesh HTTP request duration in seconds";
constexpr auto PROM_METRIC_NAME_appmesh_http_requests_in_flight = "appmesh_http_requests_in_flight";
constexpr auto PROM_METRIC_HELP_appmesh_http_requests_in_flight = "Current App Mesh HTTP requests in flight";
constexpr auto PROM_METRIC_NAME_appmesh_application_process_starts_total = "appmesh_application_process_starts_total";
constexpr auto PROM_METRIC_HELP_appmesh_application_process_starts_total = "Total application process start attempts, including attach and recovery";
constexpr auto PROM_METRIC_NAME_appmesh_application_metrics_collection_errors_total = "appmesh_application_metrics_collection_errors_total";
constexpr auto PROM_METRIC_HELP_appmesh_application_metrics_collection_errors_total = "Total process metric collection errors for an application";
constexpr auto PROM_METRIC_NAME_appmesh_application_process_id = "appmesh_application_process_id";
constexpr auto PROM_METRIC_HELP_appmesh_application_process_id = "Application process ID, or zero while stopped";
constexpr auto PROM_METRIC_NAME_appmesh_application_process_resident_memory_bytes = "appmesh_application_process_resident_memory_bytes";
constexpr auto PROM_METRIC_HELP_appmesh_application_process_resident_memory_bytes = "Resident memory in the application process tree";
constexpr auto PROM_METRIC_NAME_appmesh_application_process_cpu_usage_cores = "appmesh_application_process_cpu_usage_cores";
constexpr auto PROM_METRIC_HELP_appmesh_application_process_cpu_usage_cores = "CPU usage of the application process tree in CPU cores";
constexpr auto PROM_METRIC_NAME_appmesh_application_process_open_fds = "appmesh_application_process_open_fds";
constexpr auto PROM_METRIC_HELP_appmesh_application_process_open_fds = "Open file descriptors in the application process tree";
constexpr auto PROM_METRIC_NAME_appmesh_application_enabled = "appmesh_application_enabled";
constexpr auto PROM_METRIC_HELP_appmesh_application_enabled = "Whether the application is enabled";
constexpr auto PROM_METRIC_NAME_appmesh_application_running = "appmesh_application_running";
constexpr auto PROM_METRIC_HELP_appmesh_application_running = "Whether the application process is running";
constexpr auto PROM_METRIC_NAME_appmesh_application_healthy = "appmesh_application_healthy";
constexpr auto PROM_METRIC_HELP_appmesh_application_healthy = "Whether the application health check is passing";
