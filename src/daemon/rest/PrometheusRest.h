#pragma once

#include <memory>
#include <assert.h>
#include <functional>
#include <cpprest/http_listener.h> // HTTP server
#include "../../common/HttpRequest.h"
#include "../../prom_exporter/family.h"

namespace prometheus
{
	class Counter;
	class Gauge;
	class Registry;
}; // namespace prometheus

//////////////////////////////////////////////////////////////////////////
//                 Rgistry
//                   _|_
//  CounterFamlity-1     CounterFamlity-2
//        _|_                   _|_
//  Counter1/Counter2    Counter3/Counter4
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
class PrometheusRest
{
public:
	explicit PrometheusRest(std::string ipaddress, int port);
	virtual ~PrometheusRest();

	std::shared_ptr<CounterPtr> createPromCounter(const std::string &metricName, const std::string &metricHelp, const std::map<std::string, std::string> &labels) noexcept(false);
	std::shared_ptr<GaugePtr> createPromGauge(const std::string &metricName, const std::string &metricHelp, const std::map<std::string, std::string> &labels) noexcept(false);
	const std::string collectData();

protected:
	void open();
	void close();
	void initMetrics();

private:
	void handleRest(const http_request &message, const std::map<std::string, std::function<void(const HttpRequest &)>> &restFunctions);
	void bindRestMethod(web::http::method method, std::string path, std::function<void(const HttpRequest &)> func);
	void handle_get(const HttpRequest &message);
	void handle_put(const HttpRequest &message);
	void handle_post(const HttpRequest &message);
	void handle_delete(const HttpRequest &message);
	void handle_options(const HttpRequest &message);
	void handle_error(pplx::task<void> &t);

	void apiMetrics(const HttpRequest &message);

private:
	std::unique_ptr<web::http::experimental::listener::http_listener> m_listener;
	// API functions
	std::map<std::string, std::function<void(const HttpRequest &)>> m_restGetFunctions;
	std::map<std::string, std::function<void(const HttpRequest &)>> m_restPutFunctions;
	std::map<std::string, std::function<void(const HttpRequest &)>> m_restPstFunctions;
	std::map<std::string, std::function<void(const HttpRequest &)>> m_restDelFunctions;
	bool m_promEnabled;
	std::recursive_mutex m_mutex;

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
