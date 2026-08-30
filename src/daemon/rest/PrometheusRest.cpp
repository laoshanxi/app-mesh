// src/daemon/rest/PrometheusRest.cpp
#include <algorithm>
#include <chrono>

#include <prometheus/counter.h>
#include <prometheus/histogram.h>
#include <prometheus/registry.h>
#include <prometheus/text_serializer.h>

#include "../../common/Utility.h"
#include "../../common/os/pstree.h"
#include "../ResourceCollection.h"
#include "PrometheusRest.h"

PrometheusRest::PrometheusRest()
{
	m_promRegistry = std::make_shared<prometheus::Registry>();
	initMetrics();
}

PrometheusRest::~PrometheusRest()
{
	const static char fname[] = "PrometheusRest::~PrometheusRest() ";
	LOG_INF << fname << "PrometheusRest destroyed";
}

void PrometheusRest::initMetrics()
{
	// Prometheus
	m_scrapeCounter = createPromCounter(
		PROM_METRIC_NAME_appmesh_metrics_scrapes_total,
		PROM_METRIC_HELP_appmesh_metrics_scrapes_total,
		{});
	m_collectionErrorCounter = createPromCounter(
		PROM_METRIC_NAME_appmesh_metrics_collection_errors_total,
		PROM_METRIC_HELP_appmesh_metrics_collection_errors_total,
		{});
	m_appmeshFileDesc = createPromGauge(
		PROM_METRIC_NAME_appmesh_process_open_fds,
		PROM_METRIC_HELP_appmesh_process_open_fds,
		{});
	m_appmeshPid = createPromGauge(
		PROM_METRIC_NAME_appmesh_process_id,
		PROM_METRIC_HELP_appmesh_process_id,
		{});
	m_appmeshPid->metric().Set(ResourceCollection::instance()->getPid());
	m_buildInfo = createPromGauge(
		"appmesh_build_info", "App Mesh build information",
		{{"version", __MICRO_VAR__(BUILD_TAG)}});
	m_buildInfo->metric().Set(1);
}

std::shared_ptr<CounterMetric> PrometheusRest::createPromCounter(const std::string &metricName, const std::string &metricHelp, const std::map<std::string, std::string> &labels)
{
	std::lock_guard<std::mutex> guard(m_familyMutex);
	auto familyIt = m_counterFamilies.find(metricName);
	if (familyIt == m_counterFamilies.end())
	{
		auto &family = prometheus::BuildCounter().Name(metricName).Help(metricHelp).Register(*m_promRegistry);
		familyIt = m_counterFamilies.emplace(metricName, &family).first;
	}
	return std::make_shared<CounterMetric>(m_promRegistry, *familyIt->second, metricName, labels);
}

std::shared_ptr<GaugeMetric> PrometheusRest::createPromGauge(const std::string &metricName, const std::string &metricHelp, const std::map<std::string, std::string> &labels)
{
	std::lock_guard<std::mutex> guard(m_familyMutex);
	auto familyIt = m_gaugeFamilies.find(metricName);
	if (familyIt == m_gaugeFamilies.end())
	{
		auto &family = prometheus::BuildGauge().Name(metricName).Help(metricHelp).Register(*m_promRegistry);
		familyIt = m_gaugeFamilies.emplace(metricName, &family).first;
	}
	return std::make_shared<GaugeMetric>(m_promRegistry, *familyIt->second, metricName, labels);
}

std::shared_ptr<HistogramMetric> PrometheusRest::createPromHistogram(const std::string &metricName, const std::string &metricHelp,
	const std::map<std::string, std::string> &labels, const std::vector<double> &buckets)
{
	std::lock_guard<std::mutex> guard(m_familyMutex);
	auto familyIt = m_histogramFamilies.find(metricName);
	if (familyIt == m_histogramFamilies.end())
	{
		auto &family = prometheus::BuildHistogram().Name(metricName).Help(metricHelp).Register(*m_promRegistry);
		familyIt = m_histogramFamilies.emplace(metricName, &family).first;
	}
	return std::make_shared<HistogramMetric>(m_promRegistry, *familyIt->second, metricName, labels, buckets);
}

namespace
{
	const std::vector<double> HTTP_DURATION_BUCKETS = {
		0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 30.0};

	std::string httpMetricKey(const std::string &method, const std::string &route, const std::string &suffix = {})
	{
		return method + "\n" + route + "\n" + suffix;
	}

	std::string httpStatusClass(int statusCode)
	{
		if (statusCode >= 100 && statusCode <= 599)
			return std::to_string(statusCode / 100) + "xx";
		return "unreplied";
	}
}

void PrometheusRest::httpRequestStarted(const std::string &method, const std::string &route)
{
	std::shared_ptr<GaugeMetric> inFlight;
	{
		std::lock_guard<std::mutex> guard(m_httpMetricMutex);
		auto &slot = m_httpInflightGauges[httpMetricKey(method, route)];
		if (!slot)
			slot = createPromGauge(PROM_METRIC_NAME_appmesh_http_requests_in_flight,
				PROM_METRIC_HELP_appmesh_http_requests_in_flight, {{"method", method}, {"route", route}});
		inFlight = slot;
	}
	inFlight->metric().Increment();
}

void PrometheusRest::httpRequestFinished(const std::string &method, const std::string &route, int statusCode, double durationSeconds)
{
	const auto statusClass = httpStatusClass(statusCode);
	const auto status = statusCode >= 100 && statusCode <= 599
		? std::to_string(statusCode) : std::string("unreplied");
	std::shared_ptr<CounterMetric> counter;
	std::shared_ptr<GaugeMetric> inFlight;
	std::shared_ptr<HistogramMetric> duration;
	{
		std::lock_guard<std::mutex> guard(m_httpMetricMutex);
		auto &counterSlot = m_httpRequestCounters[httpMetricKey(method, route, status)];
		if (!counterSlot)
			counterSlot = createPromCounter(PROM_METRIC_NAME_appmesh_http_requests_total,
				PROM_METRIC_HELP_appmesh_http_requests_total,
				{{"method", method}, {"route", route}, {"status_code", status}, {"status_class", statusClass}});
		counter = counterSlot;

		auto &durationSlot = m_httpDurationHistograms[httpMetricKey(method, route)];
		if (!durationSlot)
			durationSlot = createPromHistogram(PROM_METRIC_NAME_appmesh_http_request_duration_seconds,
				PROM_METRIC_HELP_appmesh_http_request_duration_seconds,
				{{"method", method}, {"route", route}}, HTTP_DURATION_BUCKETS);
		duration = durationSlot;

		auto &inFlightSlot = m_httpInflightGauges[httpMetricKey(method, route)];
		if (!inFlightSlot)
			inFlightSlot = createPromGauge(PROM_METRIC_NAME_appmesh_http_requests_in_flight,
				PROM_METRIC_HELP_appmesh_http_requests_in_flight, {{"method", method}, {"route", route}});
		inFlight = inFlightSlot;
	}
	counter->metric().Increment();
	duration->metric().Observe(std::max(0.0, durationSeconds));
	inFlight->metric().Decrement();
}

std::string PrometheusRest::collectData()
{
	if (m_scrapeCounter)
	{
		m_scrapeCounter->metric().Increment();
	}
	// Keep serialization state local to each scrape.
	prometheus::TextSerializer promSerializer;
	auto result = promSerializer.Serialize(m_promRegistry->Collect());
	m_scrapeGeneration.fetch_add(1, std::memory_order_relaxed);
	return result;
}

void PrometheusRest::refreshProcessMetrics(void *processSnapshot)
{
	if (processSnapshot == nullptr)
	{
		m_appmeshFileDesc->metric().Set(0);
		m_collectionErrorCounter->metric().Increment();
		return;
	}
	try
	{
		auto processTree = os::pstree(0, processSnapshot);
		if (processTree)
		{
			m_appmeshFileDesc->metric().Set(processTree->totalFileDescriptors());
			return;
		}
	}
	catch (const std::exception &ex)
	{
		LOG_ERR << "Prometheus process collection failed: " << ex.what();
	}
	catch (...)
	{
		LOG_ERR << "Prometheus process collection failed";
	}
	m_appmeshFileDesc->metric().Set(0);
	m_collectionErrorCounter->metric().Increment();
}

uint64_t PrometheusRest::scrapeGeneration() const
{
	return m_scrapeGeneration.load(std::memory_order_relaxed);
}

CounterMetric::CounterMetric(std::shared_ptr<prometheus::Registry> registry, prometheus::Family<prometheus::Counter> &family, const std::string &name, std::map<std::string, std::string> label)
	: m_metric(nullptr), m_family(&family), m_promRegistry(registry), m_name(name)
{
	const static char fname[] = "CounterMetric::CounterMetric() ";
	prometheus::Labels commonLabels = {{"host", MY_HOST_NAME}};
	commonLabels.insert(label.begin(), label.end());
	m_metric = &((family.Add(commonLabels)));

	LOG_DBG << fname << "metric " << m_name << " added";
}

CounterMetric::~CounterMetric()
{
	const static char fname[] = "CounterMetric::~CounterMetric() ";
	if (m_family && m_metric)
		m_family->Remove(m_metric);
	LOG_DBG << fname << "metric " << m_name << " removed";
}

prometheus::Counter &CounterMetric::metric()
{
	return *m_metric;
}

GaugeMetric::GaugeMetric(std::shared_ptr<prometheus::Registry> registry, prometheus::Family<prometheus::Gauge> &family, const std::string &name, std::map<std::string, std::string> label)
	: m_metric(nullptr), m_family(&family), m_promRegistry(registry), m_name(name)
{
	const static char fname[] = "GaugeMetric::GaugeMetric() ";

	prometheus::Labels commonLabels = {{"host", MY_HOST_NAME}};
	commonLabels.insert(label.begin(), label.end());
	m_metric = &((family.Add(commonLabels)));

	LOG_DBG << fname << "metric " << m_name << " added";
}

GaugeMetric::~GaugeMetric()
{
	const static char fname[] = "GaugeMetric::~GaugeMetric() ";
	if (m_family && m_metric)
		m_family->Remove(m_metric);
	LOG_DBG << fname << "metric " << m_name << " removed";
}

prometheus::Gauge &GaugeMetric::metric()
{
	return *m_metric;
}

HistogramMetric::HistogramMetric(std::shared_ptr<prometheus::Registry> registry,
	prometheus::Family<prometheus::Histogram> &family, const std::string &name,
	std::map<std::string, std::string> label, const std::vector<double> &buckets)
	: m_metric(nullptr), m_family(&family), m_promRegistry(registry), m_name(name)
{
	prometheus::Labels commonLabels = {{"host", MY_HOST_NAME}};
	commonLabels.insert(label.begin(), label.end());
	m_metric = &(family.Add(commonLabels, buckets));
}

HistogramMetric::~HistogramMetric()
{
	if (m_family && m_metric)
		m_family->Remove(m_metric);
}

prometheus::Histogram &HistogramMetric::metric()
{
	return *m_metric;
}
