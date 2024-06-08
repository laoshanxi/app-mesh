#pragma once

#include <map>
#include <memory>
#include <mutex>
#include <string>

#include <nlohmann/json.hpp>

//////////////////////////////////////////////////////////////////////////
/// Label
//////////////////////////////////////////////////////////////////////////
class Label
{
public:
	Label();
	virtual ~Label();

	nlohmann::json AsJson() const;
	static const std::shared_ptr<Label> FromJson(const nlohmann::json &obj) noexcept(false);
	bool operator==(const std::shared_ptr<Label> &label);

	void addLabel(const std::string &name, const std::string &value);
	void delLabel(const std::string &name);

	void readDefaultLabel();

	bool match(const std::shared_ptr<Label> &condition) const;

private:
	std::map<std::string, std::string> m_labels;
	mutable std::recursive_mutex m_mutex;
};
