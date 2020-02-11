#pragma once

#include <string>
#include <map>
#include <memory>
#include <mutex>
#include <cpprest/json.h>

//////////////////////////////////////////////////////////////////////////
/// Label
//////////////////////////////////////////////////////////////////////////
class Label
{
public:
	Label();
	virtual ~Label();

	virtual web::json::value AsJson();
	static const std::shared_ptr<Label> FromJson(const web::json::value& obj) noexcept(false);
	bool operator==(const std::shared_ptr<Label>& label);

	void addLabel(const std::string& name, const std::string& value);
	void delLabel(const std::string& name);

	bool match(const std::shared_ptr<Label>& label) const;

private:
	std::map<std::string, std::string> m_labels;
	std::recursive_mutex m_mutex;

};
