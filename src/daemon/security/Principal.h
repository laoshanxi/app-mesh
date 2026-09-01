#pragma once

#include <nlohmann/json.hpp>

#include <string>

/// Identity established by the configured Dex issuer.
/// Authorization keys are derived exclusively from (issuer, subject); display claims are
/// deliberately excluded because they are mutable and therefore unsuitable for ownership.
class Principal
{
public:
	enum class Kind
	{
		User,
		Service,
		System
	};

	Principal(std::string issuer, std::string subject, Kind kind = Kind::User);

	const std::string &id() const;
	const std::string &issuer() const;
	const std::string &subject() const;
	Kind kind() const;

	void displayName(std::string value);
	void email(std::string value);
	void connectorId(std::string value);

	const std::string &displayName() const;
	const std::string &email() const;
	const std::string &connectorId() const;

	nlohmann::json asJson() const;

	static std::string stableId(const std::string &issuer, const std::string &subject);
	static const char *kindName(Kind kind);

private:
	std::string m_id;
	std::string m_issuer;
	std::string m_subject;
	Kind m_kind;
	std::string m_displayName;
	std::string m_email;
	std::string m_connectorId;
};
