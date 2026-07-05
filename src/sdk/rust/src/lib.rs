// lib.rs
//! AppMesh SDK for Rust

mod client_builder;
mod client_http;
mod client_tcp;
mod client_wss;
mod constants;
mod error;
mod models;
mod persistent_jar;
mod requester;
mod response_ext;
mod subscribe;
mod wire_messages;
mod wait_subscribe;
mod tcp_transport;
pub mod tls_config;
mod wss_transport;
mod server_http;
mod server_tcp;
mod server_wss;

pub use client_builder::*;
pub use client_http::AppMeshClient;
pub use client_tcp::AppMeshClientTCP;
pub use client_wss::AppMeshClientWSS;
pub use error::{AppMeshError, TransportError};
pub use models::{
    AppEvent, AppOutput, AppRun, Application, ApplicationBuilder, Behavior, DailyLimitation,
    ExitAction, OutputFn, OutputHandler, Permission, ResourceLimitation, SubscriptionResult, User,
    print_output_handler,
};
// Canonical cross-SDK worker names (match the Python/Go SDKs).
pub use server_http::AppMeshWorker;
pub use server_tcp::AppMeshWorkerTCP;
pub use server_wss::AppMeshWorkerWSS;
pub use constants::EVENT_TYPE_DISCONNECTED;
pub use subscribe::EventCallback;
