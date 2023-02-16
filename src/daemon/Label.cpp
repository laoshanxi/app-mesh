#ifdef __GNUC__
#include <features.h>
#if __GNUC_PREREQ(5, 4)
#include <wildcards/wildcards.hpp>
#endif
#endif

#include "../common/Utility.h"
#include "Label.h"
#include "ResourceCollection.h"

Label::Label()
{
}

Label::~Label()
{
}

nlohmann::json Label::AsJson() const
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	auto tags = nlohmann::json::object();
	for (auto &tag : m_labels)
	{
		tags[tag.first] = std::string(tag.second);
	}
	return tags;
}

const std::shared_ptr<Label> Label::FromJson(const nlohmann::json &obj)
{
	std::shared_ptr<Label> label = std::make_shared<Label>();
	if (!obj.is_null() && obj.is_object())
	{
		for (auto &lblJson : obj.items())
		{
			std::string labelKey = (lblJson.key());
			label->m_labels[labelKey] = (lblJson.value().get<std::string>());
		}
	}
	return label;
}

bool Label::operator==(const std::shared_ptr<Label> &label)
{
	if (!label)
		return false;
	if (m_labels.size() != label->m_labels.size())
		return false;
	return this->match(label);
}

void Label::addLabel(const std::string &name, const std::string &value)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	m_labels[name] = value;
}

void Label::delLabel(const std::string &name)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (m_labels.count(name))
		m_labels.erase(name);
}

bool Label::match(const std::shared_ptr<Label> &condition) const
{
	if (!condition)
		return false;
	for (const auto &la : condition->m_labels)
	{
		const auto &key = la.first;
		const auto &val = la.second;
#if __GNUC_PREREQ(5, 4)
		// support wildcards for gcc version upper than 5.4
		if (!(m_labels.count(key) && (m_labels.find(key)->second == val || wildcards::make_matcher(val).matches(m_labels.find(key)->second))))
#else
		if (!(m_labels.count(key) && (m_labels.find(key)->second == val)))
#endif
		{
			return false;
		}
	}
	return true;
}
