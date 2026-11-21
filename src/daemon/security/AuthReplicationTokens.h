#pragma once

#include <string>
#include <vector>

/// Per-follower replication tokens for the owner's policy snapshot endpoint.
///
/// The token file holds one accepted bearer per line, with an audit label
/// after whitespace:
///
///     77a1...d0 slave1     per-follower token, revocable alone
///     # comment lines are ignored
///
/// A line without a label is not an accepted entry. Revoking one follower is
/// a file edit: the endpoint re-reads the file on every request.
namespace AuthReplication
{
// Deployment env names for the replication token source; the single spelling
// of every key (daemon reads live in AuthReplicator, RestHandler,
// AuthorizationStore and VaultClient).
inline constexpr const char *ENV_FROM = "APPMESH_AUTH_REPLICATION_FROM";
inline constexpr const char *ENV_TOKEN_FILE = "APPMESH_AUTH_REPLICATION_TOKEN_FILE";
inline constexpr const char *ENV_CA = "APPMESH_AUTH_REPLICATION_CA";
inline constexpr const char *ENV_INTERVAL = "APPMESH_AUTH_REPLICATION_INTERVAL";
inline constexpr const char *ENV_TOKEN_SOURCE = "APPMESH_AUTH_REPLICATION_TOKEN_SOURCE";
inline constexpr const char *ENV_VAULT_ADDR = "APPMESH_AUTH_REPLICATION_TOKEN_VAULT_ADDR";
inline constexpr const char *ENV_VAULT_TOKEN_FILE = "APPMESH_AUTH_REPLICATION_TOKEN_VAULT_TOKEN_FILE";
inline constexpr const char *ENV_LABEL = "APPMESH_AUTH_REPLICATION_LABEL";

struct AcceptedToken
{
	std::string token;
	std::string label;
};

/// Parses the token file content; lines without a label are skipped.
std::vector<AcceptedToken> parseTokenFile(const std::string &fileContent);

/// Constant-time match of the presented bearer against an explicit accepted
/// set (file or Vault sourced). Every entry is compared, without early exit,
/// so the matching position is not observable through timing. Returns the
/// matched label, or an empty string when nothing matches.
std::string matchToken(const std::vector<AcceptedToken> &tokens, const std::string &presented);

/// File-content convenience wrapper: parse, then match.
std::string matchToken(const std::string &fileContent, const std::string &presented);

/// True when the follower label holds only letters, digits, '.', '_' or '-'.
/// The same whitelist the shell tooling applies, so an operator typo fails in
/// the tooling instead of building a Vault URL the label was never meant for.
bool isValidLabel(const std::string &label);
} // namespace AuthReplication
