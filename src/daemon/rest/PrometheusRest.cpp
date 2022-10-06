#include <ace/OS.h>
#include <boost/algorithm/string_regex.hpp>

#include "../../common/Utility.h"
#include "../../common/os/process.hpp"
#include "../../common/os/pstree.hpp"
#include "../../prom_exporter/counter.h"
#include "../../prom_exporter/registry.h"
#include "../../prom_exporter/text_serializer.h"
#include "../Configuration.h"
#include "../ResourceCollection.h"
#include "PrometheusRest.h"
#include "RestBase.h"

std::shared_ptr<PrometheusRest> PrometheusRest::m_instance;
constexpr auto CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8";
constexpr auto METRIC_PATH = "/metrics";

PrometheusRest::PrometheusRest()
	: RestBase(), m_scrapeCounter(0)
{
	m_promRegistry = std::make_shared<prometheus::Registry>();
	bindRestMethod(web::http::methods::GET, METRIC_PATH, std::bind(&PrometheusRest::apiMetrics, this, std::placeholders::_1));
	initMetrics();
}

PrometheusRest::~PrometheusRest()
{
	const static char fname[] = "PrometheusRest::~PrometheusRest() ";
	LOG_INF << fname << "Entered";
}

void PrometheusRest::initMetrics()
{
	// Prometheus
	m_scrapeCounter = createPromCounter(
		PROM_METRIC_NAME_appmesh_prom_scrape_count,
		PROM_METRIC_HELP_appmesh_prom_scrape_count,
		{});
	m_appmeshFileDesc = createPromGauge(
		PROM_METRIC_NAME_appmesh_prom_file_descriptor,
		PROM_METRIC_HELP_appmesh_prom_file_descriptor,
		{});
	// Const Gauge counter
	m_promGauge = createPromGauge(
		PROM_METRIC_NAME_appmesh_prom_scrape_up,
		PROM_METRIC_HELP_appmesh_prom_scrape_up,
		{});
	if (m_promGauge)
		m_promGauge->metric().Set(1);

	auto listenAddress = Configuration::instance()->getRestListenAddress() + ":" + std::to_string(Configuration::instance()->getRestListenPort());
	m_restGetCounter = createPromCounter(
		PROM_METRIC_NAME_appmesh_http_request_count, PROM_METRIC_HELP_appmesh_http_request_count,
		{{"method", web::http::methods::GET}, {"listen", listenAddress}});
	m_restPutCounter = createPromCounter(
		PROM_METRIC_NAME_appmesh_http_request_count, PROM_METRIC_HELP_appmesh_http_request_count,
		{{"method", web::http::methods::PUT}, {"listen", listenAddress}});
	m_restDelCounter = createPromCounter(
		PROM_METRIC_NAME_appmesh_http_request_count, PROM_METRIC_HELP_appmesh_http_request_count,
		{{"method", web::http::methods::DEL}, {"listen", listenAddress}});
	m_restPostCounter = createPromCounter(
		PROM_METRIC_NAME_appmesh_http_request_count, PROM_METRIC_HELP_appmesh_http_request_count,
		{{"method", web::http::methods::POST}, {"listen", listenAddress}});
}

std::shared_ptr<CounterMetric> PrometheusRest::createPromCounter(const std::string &metricName, const std::string &metricHelp, const std::map<std::string, std::string> &labels)
{
	return std::make_shared<CounterMetric>(m_promRegistry, metricName, metricHelp, labels);
}

std::shared_ptr<GaugeMetric> PrometheusRest::createPromGauge(const std::string &metricName, const std::string &metricHelp, const std::map<std::string, std::string> &labels)
{
	return std::make_shared<GaugeMetric>(m_promRegistry, metricName, metricHelp, labels);
}

void PrometheusRest::handleRest(const HttpRequest &message, const std::map<std::string, std::function<void(const HttpRequest &)>> &restFunctions)
{
	if (message.m_method == web::http::methods::GET && message.m_relative_uri != METRIC_PATH)
		PROM_COUNTER_INCREASE(m_restGetCounter)
	else if (message.m_method == web::http::methods::PUT)
		PROM_COUNTER_INCREASE(m_restPutCounter)
	else if (message.m_method == web::http::methods::POST)
		PROM_COUNTER_INCREASE(m_restPostCounter)
	else if (message.m_method == web::http::methods::DEL)
		PROM_COUNTER_INCREASE(m_restDelCounter)

	RestBase::handleRest(message, restFunctions);
}

const std::string PrometheusRest::collectData()
{
	m_collectTime = ACE_OS::time();
	// leave a static text serializer here
	static auto promSerializer = std::unique_ptr<prometheus::Serializer>(new prometheus::TextSerializer());
	return promSerializer->Serialize(m_promRegistry->Collect());
}

bool PrometheusRest::collected()
{
	if (ACE_OS::time() - m_collectTime > 5)
	{
		return false;
	}
	return true;
}

void PrometheusRest::apiMetrics(const HttpRequest &message)
{
	const static char fname[] = "PrometheusRest::apiMetrics() ";
	LOG_DBG << fname << "Entered";

	if (m_scrapeCounter)
	{
		m_scrapeCounter->metric().Increment();
	}
	if (m_appmeshFileDesc)
	{
		m_appmeshFileDesc->metric().Set(os::pstree()->totalFileDescriptors());
	}

	message.saveReply(status_codes::OK, collectData(), CONTENT_TYPE);
}

CounterMetric::CounterMetric(std::shared_ptr<prometheus::Registry> registry, const std::string &name, const std::string &help, std::map<std::string, std::string> label)
	: m_metric(nullptr), m_family(nullptr), m_promRegistry(registry), m_name(name), m_help(help), m_label(label)
{
	const static char fname[] = "CounterMetric::CounterMetric() ";
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

CounterMetric::~CounterMetric()
{
	const static char fname[] = "CounterMetric::~CounterMetric() ";
	m_family->Remove(m_metric);
	LOG_DBG << fname << "metric " << m_name << " removed";
}

prometheus::Counter &CounterMetric::metric()
{
	return *m_metric;
}

GaugeMetric::GaugeMetric(std::shared_ptr<prometheus::Registry> registry, const std::string &name, const std::string &help, std::map<std::string, std::string> label)
	: m_metric(nullptr), m_family(nullptr), m_promRegistry(registry), m_name(name), m_help(help), m_label(label)
{
	const static char fname[] = "GaugeMetric::GaugeMetric() ";

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

GaugeMetric::~GaugeMetric()
{
	const static char fname[] = "GaugeMetric::~GaugeMetric() ";
	m_family->Remove(m_metric);
	LOG_DBG << fname << "metric " << m_name << " removed";
}

prometheus::Gauge &GaugeMetric::metric()
{
	return *m_metric;
}
