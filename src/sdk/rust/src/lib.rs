// lib.rs
//! AppMesh SDK for Rust

mod client_builder;
mod client_http;
mod client_tcp;
mod client_wss;
mod constants;
mod error;
mod models;
mod oauth;
mod requester;
mod request_signature;
mod response_ext;
mod subscribe;
mod tcp_transport;
pub mod tls_config;
mod wait_subscribe;
mod wire_messages;
mod worker_http;
mod worker_tcp;
mod worker_wss;
mod wss_transport;

pub use client_builder::*;
pub use client_http::{AppMeshClient, RunStream, SseEnd, SseStream};
pub use client_tcp::AppMeshClientTCP;
pub use client_wss::AppMeshClientWSS;
pub use error::{AppMeshError, TransportError};
pub use request_signature::RequestSigner;
pub use models::{
    print_output_handler, AppEvent, AppOutput, AppRun, Application, ApplicationBuilder, Behavior, DailyLimitation,
    ExitAction, OutputFn, OutputHandler, Permission, ResourceLimitation, SubscriptionResult,
};
pub use oauth::{
    AuthorizationRequest, DeviceAuthorization, DevicePoll, OAuthClient, OAuthConfig, OidcMetadata,
    StaticAccessTokenProvider, TokenProvider, TokenSet, TokenSetProviderOptions, DEFAULT_OAUTH_SCOPE, DEFAULT_OAUTH_SCOPES,
};
// Canonical cross-SDK worker names (match the Python/Go SDKs).
pub use constants::{EVENT_TYPE_DISCONNECTED, SYNC_RUN_OUTPUT_PAGE_BYTES, SYNC_RUN_TRUNCATED_RETENTION_SECONDS};
pub use subscribe::EventCallback;
pub use worker_http::AppMeshWorker;
pub use worker_tcp::AppMeshWorkerTCP;
pub use worker_wss::AppMeshWorkerWSS;
