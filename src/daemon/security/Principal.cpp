#include "Principal.h"

#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <utility>

#include <openssl/evp.h>

Principal::Principal(std::string issuer, std::string subject, Kind kind)
	: m_id(stableId(issuer, subject)), m_issuer(std::move(issuer)), m_subject(std::move(subject)), m_kind(kind)
{
	if (m_issuer.empty() || m_subject.empty())
		throw std::invalid_argument("OIDC principal requires non-empty issuer and subject");
}

const std::string &Principal::id() const { return m_id; }
const std::string &Principal::issuer() const { return m_issuer; }
const std::string &Principal::subject() const { return m_subject; }
Principal::Kind Principal::kind() const { return m_kind; }

void Principal::displayName(std::string value) { m_displayName = std::move(value); }
void Principal::email(std::string value) { m_email = std::move(value); }
void Principal::connectorId(std::string value) { m_connectorId = std::move(value); }

const std::string &Principal::displayName() const { return m_displayName; }
const std::string &Principal::email() const { return m_email; }
const std::string &Principal::connectorId() const { return m_connectorId; }

nlohmann::json Principal::asJson() const
{
	nlohmann::json result;
	result["principal_id"] = m_id;
	result["kind"] = kindName(m_kind);
	result["issuer"] = m_issuer;
	result["subject"] = m_subject;
	result["display_name"] = m_displayName;
	result["email"] = m_email;
	result["connector_id"] = m_connectorId;
	return result;
}

std::string Principal::stableId(const std::string &issuer, const std::string &subject)
{
	if (issuer.empty() || subject.empty())
		throw std::invalid_argument("OIDC principal requires non-empty issuer and subject");

	const std::string identity = issuer + '\0' + subject;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digestLength = 0;
	if (EVP_Digest(identity.data(), identity.size(), digest, &digestLength, EVP_sha256(), nullptr) != 1)
		throw std::runtime_error("Failed to derive OIDC principal identifier");

	std::ostringstream encoded;
	encoded << "oidc:" << std::hex << std::setfill('0');
	for (unsigned int i = 0; i < digestLength; ++i)
		encoded << std::setw(2) << static_cast<unsigned int>(digest[i]);
	return encoded.str();
}

const char *Principal::kindName(Kind kind)
{
	switch (kind)
	{
	case Kind::User:
		return "user";
	case Kind::Service:
		return "service";
	case Kind::System:
		return "system";
	}
	return "user";
}
