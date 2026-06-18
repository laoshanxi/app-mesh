package llm

import (
	"fmt"
	"os"
	"strconv"
)

// maxOutputTokens returns the API output-token cap for a provider request,
// overridable via MODELENV_MAX_OUTPUT_TOKENS (distinct from the per-turn token
// budget, which is enforced by the agent loop). Falls back to def.
func maxOutputTokens(def int) int {
	if v := os.Getenv("MODELENV_MAX_OUTPUT_TOKENS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// NewBackend selects a Backend by name (one backend per tenant; see design doc):
//
//   - "stub"      — deterministic, network-free (tests / local dev)
//   - "anthropic" — Anthropic Messages API (reads ANTHROPIC_API_KEY)
//   - "local"     — OpenAI-compatible endpoint for a self-hosted inference server
//     (vLLM / Ollama / TGI / llama.cpp; reads MODELENV_LOCAL_BASE_URL + MODELENV_MODEL)
//   - "remote"    — forwards each model call to an external reasoning service
//     (e.g. a Python agent; reads MODELENV_REMOTE_URL)
//
// All backends read credentials/endpoints from the environment — never hardcoded.
// NewBackend fails closed for unknown names rather than fabricating a provider.
func NewBackend(name string) (Backend, error) {
	switch name {
	case "", "stub":
		return NewStubBackend(), nil
	case "anthropic":
		return NewAnthropicBackend()
	case "local":
		return NewLocalBackend()
	case "remote":
		return NewRemoteBackend()
	default:
		return nil, fmt.Errorf("unknown LLM backend %q (implemented: stub, anthropic, local, remote)", name)
	}
}
