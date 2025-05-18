mod firewall;
mod state;
use anyhow::{Context, Result};

use axum::{
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::any,
    Router,
};
use axum_extra::{headers, TypedHeader};
use state::AppState;

use std::{net::SocketAddr, ops::DerefMut, sync::Arc, time::Duration};

use clap::Parser;

use tokio::{signal, sync::Mutex, time::Instant};
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value_t = 3030)]
    listen: u16,

    /// UDP Port to protect (like iptables multiport)
    #[arg(short, long)]
    protect: String,
}

async fn handler(
    key: Option<Path<String>>,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    TypedHeader(user_agent): TypedHeader<headers::UserAgent>,
) -> std::result::Result<Response, AppError> {
    if !user_agent.as_str().contains("GMod") {
        return Ok(StatusCode::FORBIDDEN.into_response());
    }

    let ip = addr.ip();

    let mut whitelist = state.whitelist.lock().await;

    if whitelist.contains_key(&ip) == false {
        whitelist.insert(ip, Instant::now());

        let mut ipset = state.ipset_session.lock().await;
        ipset.add(ip, &[])?;
    } else {
        let now = Instant::now();
        if now.duration_since(whitelist[&ip]) > Duration::from_secs(300) {
            let mut ipset = state.ipset_session.lock().await;
            ipset.del(ip)?;
            whitelist.remove(&ip);
        } else {
            whitelist.insert(ip, now);
        }
    }

    drop(whitelist);

    if let Some(path) = key {
        return Ok(Redirect::temporary(&path).into_response());
    }

    Ok(StatusCode::OK.into_response())
}

struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

async fn shutdown_signal(state: Arc<AppState>) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    let clean = || async {
        let protected_port = state.args.protect.clone();
        let ipt = &state.iptables;
        let mut binding = state.ipset_session.lock().await;
        let ipset_session = binding.deref_mut();

        firewall::clean_iptables(ipt, &protected_port).unwrap();
        firewall::clean_ipset(ipset_session).unwrap();
    };

    tokio::select! {
        _ = ctrl_c => {
            clean().await;
        },
        _ = terminate => {
            clean().await;
        },
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", &args.listen))
        .await
        .with_context(|| format!("Failed to bind to port {}", &args.listen))?;

    let ipset_session =
        firewall::setup_ipset().map_err(|e| anyhow::anyhow!("Failed to setup ipset: {}", e))?;
    let iptables = firewall::setup_iptables(&args.protect)
        .map_err(|e| anyhow::anyhow!("Failed to setup iptables: {}", e))?;

    let state = Arc::new(AppState {
        iptables,
        ipset_session: Mutex::new(ipset_session),
        whitelist: Mutex::new(std::collections::HashMap::new()),
        args,
    });
    let app = Router::new()
        .route("/", any(handler))
        .route("/{*key}", any(handler))
        .layer((
            TraceLayer::new_for_http(),
            // Graceful shutdown will wait for outstanding requests to complete. Add a timeout so
            // requests don't hang forever.
            TimeoutLayer::new(Duration::from_secs(10)),
        ))
        .with_state(state.clone());

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(state))
    .await?;

    Ok(())
}
