#include <boost/algorithm/string_regex.hpp>
#include "PrometheusRest.h"
#include "ResourceCollection.h"
#include "../common/Utility.h"
#include "../prom_exporter/text_serializer.h"

std::shared_ptr<PrometheusRest> PrometheusRest::m_instance;

PrometheusRest::PrometheusRest(std::string ipaddress, int port)
	:m_promScrapeCounter(0)
{
	const static char fname[] = "PrometheusRest::PrometheusRest() ";

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
	m_listener = std::make_shared<http_listener>(uri.to_uri());

	m_listener->support(methods::GET, std::bind(&PrometheusRest::handle_get, this, std::placeholders::_1));
	m_listener->support(methods::PUT, std::bind(&PrometheusRest::handle_put, this, std::placeholders::_1));
	m_listener->support(methods::POST, std::bind(&PrometheusRest::handle_post, this, std::placeholders::_1));
	m_listener->support(methods::DEL, std::bind(&PrometheusRest::handle_delete, this, std::placeholders::_1));
	m_listener->support(methods::OPTIONS, std::bind(&PrometheusRest::handle_options, this, std::placeholders::_1));

	// Prometheus
	initPromCounter();
	bindRestMethod(web::http::methods::GET, "/metrics", std::bind(&PrometheusRest::apiMetrics, this, std::placeholders::_1));

	this->open();

	LOG_INF << fname << "Listening for requests at:" << uri.to_string();
}

PrometheusRest::~PrometheusRest()
{
	this->close();
}

void PrometheusRest::open()
{
	m_listener->open().wait();
}

void PrometheusRest::close()
{
	m_listener->close();// .wait();
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

void PrometheusRest::handleRest(const http_request& message, std::map<utility::string_t, std::function<void(const HttpRequest&)>>& restFunctions)
{
	static char fname[] = "PrometheusRest::handle_rest() ";

	std::function<void(const HttpRequest&)> stdFunction;
	auto path = GET_STD_STRING(message.relative_uri().path());
	while (path.find("//") != std::string::npos) boost::algorithm::replace_all(path, "//", "/");

	const auto request = std::move(HttpRequest(message));

	if (path == "/" || path.empty())
	{
		request.reply(status_codes::OK, "Application Manager Prometheus Exporter");
		return;
	}

	bool findRest = false;
	for (const auto& kvp : restFunctions)
	{
		if (path == GET_STD_STRING(kvp.first) || boost::regex_match(path, boost::regex(GET_STD_STRING(kvp.first))))
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

void PrometheusRest::initPromCounter()
{
	// Prometheus
	m_promRegistry = std::make_shared<prometheus::Registry>();
	auto& counterFamily = prometheus::BuildCounter()
		.Name("appmgr_prom_scrape_count")
		.Help("prometheus scrape counter")
		.Register(*m_promRegistry);
	m_promScrapeCounter = &(counterFamily.Add(
		{ {"id", ResourceCollection::instance()->getHostName()}, {"pid", std::to_string(ResourceCollection::instance()->getPid())} }));
	// Const Gauge counter
	prometheus::BuildGauge().Name("appmgr_prom_scrape_up")
		.Help("prometheus scrape alive")
		.Register(*m_promRegistry)
		.Add({ {"id", ResourceCollection::instance()->getHostName()}, {"pid", std::to_string(ResourceCollection::instance()->getPid())} })
		.Set(1);
}

prometheus::Counter* PrometheusRest::createPromHttpCounter(std::string method)
{
	auto& counter = prometheus::BuildCounter()
		.Name("appmgr_http_request_count")
		.Help("application manager http request counter")
		.Register(*m_promRegistry)
		.Add({ {"id", ResourceCollection::instance()->getHostName()}, {"pid", std::to_string(ResourceCollection::instance()->getPid())}, {"method", method} });
	return &counter;
}

void PrometheusRest::apiMetrics(const HttpRequest& message)
{
	const static char fname[] = "PrometheusRest::apiMetrics() ";
	LOG_DBG << fname << "Entered";
	// leave a static text serializer here
	static auto promSerializer = std::unique_ptr<prometheus::Serializer>(new prometheus::TextSerializer());

	m_promScrapeCounter->Increment();

	message.reply(status_codes::OK, promSerializer->Serialize(m_promRegistry->Collect()), "text/plain; version=0.0.4");
}
