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
	
	prometheus::Counter* createAppmgrHttpCounter(std::string method);

protected:
	void open();
	void close();
	void initPromCounter();

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
	prometheus::Counter* m_promScrapeCounter;
	std::unique_ptr<prometheus::Registry> m_promRegistry;
	static std::shared_ptr<PrometheusRest> m_instance;

public:
	static std::shared_ptr<PrometheusRest> instance() { return m_instance; }
	static void instance(std::shared_ptr<PrometheusRest> instance) { m_instance = instance; };
};

#endif
