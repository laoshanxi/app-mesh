#include <boost/algorithm/string_regex.hpp>
#include "PrometheusRest.h"
#include "../prom_exporter/counter.h"
#include "../prom_exporter/registry.h"
#include "ResourceCollection.h"
#include "../common/Utility.h"
#include "../prom_exporter/text_serializer.h"

std::shared_ptr<PrometheusRest> PrometheusRest::m_instance;

PrometheusRest::PrometheusRest(std::string ipaddress, int port)
	:m_promEnabled(false), m_scrapeCounter(0)
{
	const static char fname[] = "PrometheusRest::PrometheusRest() ";
	m_promRegistry = std::make_shared<prometheus::Registry>();
	initMetrics();

	if (port)
	{
		// Construct URI
		web::uri_builder uri;
		if (ipaddress.empty())
		{
			uri.set_host("0.0.0.0");
		}
		else
		{
			uri.set_host(ipaddress);
		}
		uri.set_port(port);
		uri.set_path("/");
		uri.set_scheme("http");
		m_listener = std::make_unique<web::http::experimental::listener::http_listener>(uri.to_uri());

		m_listener->support(methods::GET, std::bind(&PrometheusRest::handle_get, this, std::placeholders::_1));
		m_listener->support(methods::PUT, std::bind(&PrometheusRest::handle_put, this, std::placeholders::_1));
		m_listener->support(methods::POST, std::bind(&PrometheusRest::handle_post, this, std::placeholders::_1));
		m_listener->support(methods::DEL, std::bind(&PrometheusRest::handle_delete, this, std::placeholders::_1));
		m_listener->support(methods::OPTIONS, std::bind(&PrometheusRest::handle_options, this, std::placeholders::_1));

		bindRestMethod(web::http::methods::GET, "/metrics", std::bind(&PrometheusRest::apiMetrics, this, std::placeholders::_1));

		this->open();
		m_promEnabled = true;
		LOG_INF << fname << "Listening for requests at:" << uri.to_string();
	}
	else
	{
		LOG_INF << fname << "Listen port not specified, Prometheus exporter will not enabled";
	}
}

PrometheusRest::~PrometheusRest()
{
	const static char fname[] = "PrometheusRest::~PrometheusRest() ";
	LOG_INF << fname << "Entered";
	this->close();
}

void PrometheusRest::open()
{
	m_listener->open().wait();
}

void PrometheusRest::close()
{
	if (m_listener != nullptr) m_listener->close().wait();
}

void PrometheusRest::handle_get(const HttpRequest& message)
{
	REST_INFO_PRINT;
	handleRest(message, m_restGetFunctions);
}

void PrometheusRest::handle_put(const HttpRequest& message)
{
	REST_INFO_PRINT;
	handleRest(message, m_restPutFunctions);
}

void PrometheusRest::handle_post(const HttpRequest& message)
{
	REST_INFO_PRINT;
	handleRest(message, m_restPstFunctions);
}

void PrometheusRest::handle_delete(const HttpRequest& message)
{
	REST_INFO_PRINT;
	handleRest(message, m_restDelFunctions);
}

void PrometheusRest::handle_options(const HttpRequest& message)
{
	message.reply(status_codes::OK);
}

void PrometheusRest::handleRest(const http_request& message, const std::map<std::string, std::function<void(const HttpRequest&)>>& restFunctions)
{
	static char fname[] = "PrometheusRest::handle_rest() ";

	std::function<void(const HttpRequest&)> stdFunction;
	auto path = Utility::stringReplace(GET_STD_STRING(message.relative_uri().path()), "//", "/");

	const auto request = std::move(HttpRequest(message));

	if (path == "/" || path.empty())
	{
		request.reply(status_codes::OK, "App Mesh Prometheus Exporter");
		return;
	}

	bool findRest = false;
	for (const auto& kvp : restFunctions)
	{
		if (path == kvp.first || boost::regex_match(path, boost::regex(kvp.first)))
		{
			findRest = true;
			stdFunction = kvp.second;
			break;
		}
	}
	if (!findRest)
	{
		request.reply(status_codes::NotFound, "Path not found");
		return;
	}

	try
	{
		stdFunction(request);
	}
	catch (const std::exception& e)
	{
		LOG_WAR << fname << "rest " << path << " failed :" << e.what();
		request.reply(web::http::status_codes::BadRequest, e.what());
	}
	catch (...)
	{
		LOG_WAR << fname << "rest " << path << " failed";
		request.reply(web::http::status_codes::BadRequest, "unknow exception");
	}
}

void PrometheusRest::bindRestMethod(web::http::method method, std::string path, std::function< void(const HttpRequest&)> func)
{
	static char fname[] = "PrometheusRest::bindRest() ";

	LOG_DBG << fname << "bind " << GET_STD_STRING(method).c_str() << " " << path;

	// bind to map
	if (method == web::http::methods::GET)
		m_restGetFunctions[path] = func;
	else if (method == web::http::methods::PUT)
		m_restPutFunctions[path] = func;
	else if (method == web::http::methods::POST)
		m_restPstFunctions[path] = func;
	else if (method == web::http::methods::DEL)
		m_restDelFunctions[path] = func;
	else
		LOG_ERR << fname << GET_STD_STRING(method).c_str() << " not supported.";
}

void PrometheusRest::handle_error(pplx::task<void>& t)
{
	const static char fname[] = "PrometheusRest::handle_error() ";

	try
	{
		t.get();
	}
	catch (const std::exception& e)
	{
		LOG_ERR << fname << e.what();
	}
	catch (...)
	{
		LOG_ERR << fname << "unknown exception";
	}
}

void PrometheusRest::initMetrics()
{
	// Prometheus
	m_scrapeCounter = createPromCounter(
		PROM_METRIC_NAME_appmgr_prom_scrape_count,
		PROM_METRIC_HELP_appmgr_prom_scrape_count,
		{}
	);
	// Const Gauge counter
	m_promGauge = createPromGauge(
		PROM_METRIC_NAME_appmgr_prom_scrape_up,
		PROM_METRIC_HELP_appmgr_prom_scrape_up,
		{}
	);
	if (m_promGauge) m_promGauge->metric().Set(1);
}



std::shared_ptr<CounterPtr> PrometheusRest::createPromCounter(const std::string& metricName, const std::string& metricHelp, const std::map<std::string, std::string>& labels)
{
	if (!m_promEnabled) return nullptr;
	return std::make_shared<CounterPtr>(m_promRegistry, metricName, metricHelp, labels);
}

std::shared_ptr<GaugePtr> PrometheusRest::createPromGauge(const std::string& metricName, const std::string& metricHelp, const std::map<std::string, std::string>& labels)
{
	if (!m_promEnabled) return nullptr;
	return std::make_shared<GaugePtr>(m_promRegistry, metricName, metricHelp, labels);
}

const std::string PrometheusRest::collectData()
{
	// leave a static text serializer here
	static auto promSerializer = std::unique_ptr<prometheus::Serializer>(new prometheus::TextSerializer());
	return std::move(promSerializer->Serialize(m_promRegistry->Collect()));
}

void PrometheusRest::apiMetrics(const HttpRequest& message)
{
	const static char fname[] = "PrometheusRest::apiMetrics() ";
	LOG_DBG << fname << "Entered";

	if (m_scrapeCounter) m_scrapeCounter->metric().Increment();

	message.reply(status_codes::OK, collectData(), "text/plain; version=0.0.4");
}

CounterPtr::CounterPtr(std::shared_ptr<prometheus::Registry> retistry, const std::string& name, const std::string& help, std::map<std::string, std::string> label)
	:m_metric(nullptr), m_family(nullptr), m_promRegistry(retistry), m_name(name), m_help(help), m_label(label)
{
	const static char fname[] = "CounterPtr::CounterPtr() ";

	std::map<std::string, std::string> commonLabels = { {"host", MY_HOST_NAME}, {"pid", std::to_string(ResourceCollection::instance()->getPid())} };
	commonLabels.insert(label.begin(), label.end());

	auto& family = prometheus::BuildCounter()
		.Name(m_name)
		.Help(help)
		.Register(*m_promRegistry);
	m_family = &family;
	m_metric = &((family.Add(commonLabels)));

	LOG_DBG << fname << "metric " << m_name << " added";
}

CounterPtr::~CounterPtr()
{
	const static char fname[] = "CounterPtr::~CounterPtr() ";
	m_family->Remove(m_metric);
	LOG_DBG << fname << "metric " << m_name << " removed";
}

prometheus::Counter& CounterPtr::metric()
{
	return *m_metric;
}

GaugePtr::GaugePtr(std::shared_ptr<prometheus::Registry> retistry, const std::string& name, const std::string& help, std::map<std::string, std::string> label)
	:m_metric(nullptr), m_family(nullptr), m_promRegistry(retistry), m_name(name), m_help(help), m_label(label)
{
	const static char fname[] = "GaugePtr::GaugePtr() ";

	std::map<std::string, std::string> commonLabels = { {"host", MY_HOST_NAME}, {"pid", std::to_string(ResourceCollection::instance()->getPid())} };
	commonLabels.insert(label.begin(), label.end());

	auto& family = prometheus::BuildGauge()
		.Name(m_name)
		.Help(help)
		.Register(*m_promRegistry);
	m_family = &family;
	m_metric = &((family.Add(commonLabels)));

	LOG_DBG << fname << "metric " << m_name << " added";
}

GaugePtr::~GaugePtr()
{
	const static char fname[] = "GaugePtr::~GaugePtr() ";
	m_family->Remove(m_metric);
	LOG_DBG << fname << "metric " << m_name << " removed";
}

prometheus::Gauge& GaugePtr::metric()
{
	return *m_metric;
}
