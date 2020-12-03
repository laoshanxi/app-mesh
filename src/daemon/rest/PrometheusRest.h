#pragma once

#include <memory>
#include <cpprest/http_listener.h> // HTTP server
#include "HttpRequest.h"
#include "RestHandler.h"
#include "../../prom_exporter/family.h"

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
// Metric Wrapper for safe access
//////////////////////////////////////////////////////////////////////////
class CounterPtr
{
public:
	explicit CounterPtr(std::shared_ptr<prometheus::Registry> retistry,
						const std::string &name, const std::string &help,
						std::map<std::string, std::string> label);

	virtual ~CounterPtr();

	prometheus::Counter &metric();

private:
	prometheus::Counter *m_metric;
	prometheus::Family<prometheus::Counter> *m_family;
	std::shared_ptr<prometheus::Registry> m_promRegistry;

	const std::string m_name;
	const std::string m_help;
	const std::map<std::string, std::string> m_label;
};

class GaugePtr
{
public:
	explicit GaugePtr(std::shared_ptr<prometheus::Registry> retistry,
					  const std::string &name, const std::string &help,
					  std::map<std::string, std::string> label);

	virtual ~GaugePtr();

	prometheus::Gauge &metric();

private:
	prometheus::Gauge *m_metric;
	prometheus::Family<prometheus::Gauge> *m_family;
	std::shared_ptr<prometheus::Registry> m_promRegistry;
	const std::string m_name;
	const std::string m_help;
	const std::map<std::string, std::string> m_label;
};

//////////////////////////////////////////////////////////////////////////
/// Prometheus Exporter REST service
//////////////////////////////////////////////////////////////////////////
class PrometheusRest : public RestHandler
{
public:
	explicit PrometheusRest(bool forward2TcpServer);
	virtual ~PrometheusRest();

	std::shared_ptr<CounterPtr> createPromCounter(const std::string &metricName, const std::string &metricHelp, const std::map<std::string, std::string> &labels) noexcept(false);
	std::shared_ptr<GaugePtr> createPromGauge(const std::string &metricName, const std::string &metricHelp, const std::map<std::string, std::string> &labels) noexcept(false);
	const std::string collectData();

protected:
	virtual void open();
	void initSelfMetrics();

private:
	void apiMetrics(const HttpRequest &message);

private:
	bool m_promEnabled;
	std::unique_ptr<web::http::experimental::listener::http_listener> m_promListener;
	// prometheus
	std::shared_ptr<prometheus::Registry> m_promRegistry;
	std::shared_ptr<CounterPtr> m_scrapeCounter;
	std::shared_ptr<GaugePtr> m_promGauge;
	static std::shared_ptr<PrometheusRest> m_instance;

public:
	static std::shared_ptr<PrometheusRest> instance() { return m_instance; }
	static void instance(std::shared_ptr<PrometheusRest> instance) { m_instance = instance; };
};
// Prometheus scrap counter
#define PROM_METRIC_NAME_appmesh_prom_scrape_count "appmesh_prom_scrape_count"
#define PROM_METRIC_HELP_appmesh_prom_scrape_count "prometheus scrape count"
// App Mesh alive
#define PROM_METRIC_NAME_appmesh_prom_scrape_up "appmesh_prom_scrape_up"
#define PROM_METRIC_HELP_appmesh_prom_scrape_up "prometheus scrape alive"
// App Mesh HTTP request count
#define PROM_METRIC_NAME_appmesh_http_request_count "appmesh_http_request_count"
#define PROM_METRIC_HELP_appmesh_http_request_count "app mesh http request count"
// Application process start count
#define PROM_METRIC_NAME_appmesh_prom_process_start_count "appmesh_prom_process_start_count"
#define PROM_METRIC_HELP_appmesh_prom_process_start_count "application process spawn count"
// Application process memory usage
#define PROM_METRIC_NAME_appmesh_prom_process_memory_gauge "appmesh_prom_process_memory_gauge"
#define PROM_METRIC_HELP_appmesh_prom_process_memory_gauge "application process memory bytes"
