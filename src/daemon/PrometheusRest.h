#ifndef PROMETHEUS_REST_H
#define PROMETHEUS_REST_H
#include <memory>
#include <cpprest/http_listener.h> // HTTP server 
#include "../common/HttpRequest.h"
#include "../prom_exporter/counter.h"
#include "../prom_exporter/registry.h"

using namespace web;
using namespace http;
using namespace utility;
using namespace http::experimental::listener;

//////////////////////////////////////////////////////////////////////////
// Prometheus Exporter REST service
//////////////////////////////////////////////////////////////////////////
class PrometheusRest
{
public:
	explicit PrometheusRest(std::string ipaddress, int port);
	virtual ~PrometheusRest();

	prometheus::Counter* createPromCounter(const std::string& metricName, const std::string& metricHelp, const std::map<std::string, std::string>& labels);
	prometheus::Gauge* createPromGauge(const std::string& metricName, const std::string& metricHelp, const std::map<std::string, std::string>& labels);
	void removeCounter(prometheus::Counter* counter);
	void removeGauge(prometheus::Gauge* gauge);

protected:
	void open();
	void close();
	void initPromMetric();

private:
	void handleRest(const http_request& message, std::map<utility::string_t, std::function<void(const HttpRequest&)>>& restFunctions);
	void bindRestMethod(web::http::method method, std::string path, std::function< void(const HttpRequest&)> func);
	void handle_get(const HttpRequest& message);
	void handle_put(const HttpRequest& message);
	void handle_post(const HttpRequest& message);
	void handle_delete(const HttpRequest& message);
	void handle_options(const HttpRequest& message);
	void handle_error(pplx::task<void>& t);

	void apiMetrics(const HttpRequest& message);

private:
	std::unique_ptr<http_listener> m_listener;
	// API functions
	std::map<utility::string_t, std::function<void(const HttpRequest&)>> m_restGetFunctions;
	std::map<utility::string_t, std::function<void(const HttpRequest&)>> m_restPutFunctions;
	std::map<utility::string_t, std::function<void(const HttpRequest&)>> m_restPstFunctions;
	std::map<utility::string_t, std::function<void(const HttpRequest&)>> m_restDelFunctions;

	std::recursive_mutex m_mutex;

	// prometheus
	std::unique_ptr<prometheus::Registry> m_promRegistry;
	prometheus::Counter* m_scrapeCounter;
	std::map<prometheus::Counter*, std::string> m_metricCounters;
	std::map<prometheus::Gauge*, std::string> m_metricGauge;

public:
	static std::shared_ptr<PrometheusRest> m_instance;
	static std::shared_ptr<PrometheusRest> instance() { return m_instance; }
	static void instance(std::shared_ptr<PrometheusRest> instance) { m_instance = instance; };
};
// Prometheus scrap counter
#define PROM_METRIC_NAME_appmgr_prom_scrape_count "appmgr_prom_scrape_count"
#define PROM_METRIC_HELP_appmgr_prom_scrape_count "prometheus scrape count"
// Appmanager alive
#define PROM_METRIC_NAME_appmgr_prom_scrape_up "appmgr_prom_scrape_up"
#define PROM_METRIC_HELP_appmgr_prom_scrape_up "prometheus scrape alive"
// Appmanager HTTP request count
#define PROM_METRIC_NAME_appmgr_http_request_count "appmgr_http_request_count"
#define PROM_METRIC_HELP_appmgr_http_request_count "application manager http request count"
// Application process start count
#define PROM_METRIC_NAME_appmgr_prom_process_start_count "appmgr_prom_process_start_count"
#define PROM_METRIC_HELP_appmgr_prom_process_start_count "application process spawn count"
// Application process memory usage
#define PROM_METRIC_NAME_appmgr_prom_process_memory_gauge "appmgr_prom_process_memory_gauge"
#define PROM_METRIC_HELP_appmgr_prom_process_memory_gauge "application process memory bytes"

#endif
