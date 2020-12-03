#include <boost/algorithm/string_regex.hpp>
#include "PrometheusRest.h"
#include "../../prom_exporter/counter.h"
#include "../../prom_exporter/registry.h"
#include "../../prom_exporter/text_serializer.h"
#include "../ResourceCollection.h"
#include "../../common/Utility.h"
#include "../Configuration.h"

std::shared_ptr<PrometheusRest> PrometheusRest::m_instance;

PrometheusRest::PrometheusRest(bool forward2TcpServer)
	: RestHandler(forward2TcpServer), m_promEnabled(true), m_scrapeCounter(0)
{
	m_promRegistry = std::make_shared<prometheus::Registry>();
	bindRestMethod(web::http::methods::GET, "/metrics", std::bind(&PrometheusRest::apiMetrics, this, std::placeholders::_1));
	if (Configuration::instance()->getPromListenPort())
	{
		initSelfMetrics();
	}
}

void PrometheusRest::open()
{
	const static char fname[] = "PrometheusRest::open() ";

	RestHandler::open();

	std::string ipaddress = Configuration::instance()->getRestListenAddress();
	ipaddress = ipaddress.empty() ? std::string("0.0.0.0") : ipaddress;
	const int port = Configuration::instance()->getPromListenPort();
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
		m_promListener = std::make_unique<web::http::experimental::listener::http_listener>(uri.to_uri());
		m_promListener->support(methods::GET, std::bind(&PrometheusRest::handle_get, this, std::placeholders::_1));
		m_promListener->support(methods::PUT, std::bind(&PrometheusRest::handle_put, this, std::placeholders::_1));
		m_promListener->support(methods::POST, std::bind(&PrometheusRest::handle_post, this, std::placeholders::_1));
		m_promListener->support(methods::DEL, std::bind(&PrometheusRest::handle_delete, this, std::placeholders::_1));
		m_promListener->support(methods::OPTIONS, std::bind(&PrometheusRest::handle_options, this, std::placeholders::_1));

		m_promListener->open().wait();
		LOG_INF << fname << "Prometheus Exporter listening for requests at:" << uri.to_string();
	}
	else
	{
		m_promEnabled = false;
		LOG_INF << fname << "Listen port not specified, Prometheus exporter will not enabled";
	}
}

PrometheusRest::~PrometheusRest()
{
	const static char fname[] = "PrometheusRest::~PrometheusRest() ";
	LOG_INF << fname << "Entered";
	try
	{
		if (m_listener != nullptr)
			m_listener->close().wait();
	}
	catch (...)
	{
		LOG_WAR << fname << "failed";
	}
}

void PrometheusRest::initSelfMetrics()
{
	// Prometheus
	m_scrapeCounter = createPromCounter(
		PROM_METRIC_NAME_appmesh_prom_scrape_count,
		PROM_METRIC_HELP_appmesh_prom_scrape_count,
		{});
	// Const Gauge counter
	m_promGauge = createPromGauge(
		PROM_METRIC_NAME_appmesh_prom_scrape_up,
		PROM_METRIC_HELP_appmesh_prom_scrape_up,
		{});
	if (m_promGauge)
		m_promGauge->metric().Set(1);
}

std::shared_ptr<CounterPtr> PrometheusRest::createPromCounter(const std::string &metricName, const std::string &metricHelp, const std::map<std::string, std::string> &labels)
{
	if (!m_promEnabled)
		return nullptr;
	return std::make_shared<CounterPtr>(m_promRegistry, metricName, metricHelp, labels);
}

std::shared_ptr<GaugePtr> PrometheusRest::createPromGauge(const std::string &metricName, const std::string &metricHelp, const std::map<std::string, std::string> &labels)
{
	if (!m_promEnabled)
		return nullptr;
	return std::make_shared<GaugePtr>(m_promRegistry, metricName, metricHelp, labels);
}

const std::string PrometheusRest::collectData()
{
	// leave a static text serializer here
	static auto promSerializer = std::unique_ptr<prometheus::Serializer>(new prometheus::TextSerializer());
	return std::move(promSerializer->Serialize(m_promRegistry->Collect()));
}

void PrometheusRest::apiMetrics(const HttpRequest &message)
{
	const static char fname[] = "PrometheusRest::apiMetrics() ";
	LOG_DBG << fname << "Entered";

	if (m_scrapeCounter)
		m_scrapeCounter->metric().Increment();

	message.reply(status_codes::OK, collectData(), "text/plain; version=0.0.4");
}

CounterPtr::CounterPtr(std::shared_ptr<prometheus::Registry> registry, const std::string &name, const std::string &help, std::map<std::string, std::string> label)
	: m_metric(nullptr), m_family(nullptr), m_promRegistry(registry), m_name(name), m_help(help), m_label(label)
{
	const static char fname[] = "CounterPtr::CounterPtr() ";

	std::map<std::string, std::string> commonLabels = {{"host", MY_HOST_NAME}, {"pid", std::to_string(ResourceCollection::instance()->getPid())}};
	commonLabels.insert(label.begin(), label.end());

	auto &family = prometheus::BuildCounter()
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

prometheus::Counter &CounterPtr::metric()
{
	return *m_metric;
}

GaugePtr::GaugePtr(std::shared_ptr<prometheus::Registry> registry, const std::string &name, const std::string &help, std::map<std::string, std::string> label)
	: m_metric(nullptr), m_family(nullptr), m_promRegistry(registry), m_name(name), m_help(help), m_label(label)
{
	const static char fname[] = "GaugePtr::GaugePtr() ";

	std::map<std::string, std::string> commonLabels = {{"host", MY_HOST_NAME}, {"pid", std::to_string(ResourceCollection::instance()->getPid())}};
	commonLabels.insert(label.begin(), label.end());

	auto &family = prometheus::BuildGauge()
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

prometheus::Gauge &GaugePtr::metric()
{
	return *m_metric;
}
