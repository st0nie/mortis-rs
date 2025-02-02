use anyhow::Result;
use axum::{
    extract::{ConnectInfo, Path, State},
    response::Redirect,
    routing::any,
};
use std::{net::SocketAddr, ops::DerefMut};

use clap::Parser;

use ipset::types::HashIp;
use ipset::Session;
use iptables::IPTables;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Router,
};

use std::sync::Arc;

use std::time::Duration;
use tokio::signal;
use tokio::sync::Mutex;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

const IPTABLES_CHAIN: &str = "MORTIS";
const MORTIS_IPSET: &str = "mortis-whitelist";

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
    State(ipset_session): State<Arc<Mutex<Session<HashIp>>>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> std::result::Result<Response, AppError> {
    if ipset_session.lock().await.test(addr.ip())? {
        ipset_session.lock().await.del(addr.ip())?;
    }
    ipset_session.lock().await.add(addr.ip(), &[])?;
    if key.is_some() {
        return Ok(Redirect::temporary(&key.unwrap()).into_response());
    }

    Ok(format!(
        "ip:{} path:{}",
        addr.ip(),
        key.unwrap_or(Path("/".to_string())).0
    )
    .into_response())
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

fn setup_ipset() -> Result<Session<HashIp>> {
    let mut session: Session<HashIp> = Session::<HashIp>::new(MORTIS_IPSET.to_string());
    session.create(|builder| {
        builder
            .with_ipv6(false)?
            .with_timeout(300)?
            .with_forceadd()?
            .build()
    })?;

    Ok(session)
}

fn clean_ipset(ipset_session: &mut Session<HashIp>) -> Result<()> {
    ipset_session.flush()?;
    ipset_session.destroy()?;
    Ok(())
}

fn setup_iptables(protected_port: String) -> Result<IPTables> {
    let ipt = iptables::new(false).unwrap();
    ipt.new_chain("filter", IPTABLES_CHAIN).unwrap();

    ipt.append(
        "filter",
        IPTABLES_CHAIN,
        "-p udp --match multiport --sports 123,53,161,3702,19 -j DROP",
    )
    .unwrap();
    ipt.append(
        "filter",
        IPTABLES_CHAIN,
        format!(
            "--match set --match-set {} src -j ACCEPT",
            MORTIS_IPSET.to_string()
        )
        .as_str(),
    )
    .unwrap();
    ipt.append("filter", IPTABLES_CHAIN,  "--match hashlimit --hashlimit 5/sec --hashlimit-burst 10 --hashlimit-mode srcip,dstport --hashlimit-name main -j RETURN").unwrap();
    ipt.append("filter", IPTABLES_CHAIN, "-j DROP").unwrap();
    ipt.insert(
        "filter",
        "INPUT",
        format!(
            "-p udp --match multiport --dports {} -j {}",
            protected_port, IPTABLES_CHAIN,
        )
        .as_str(),
        1,
    )
    .unwrap();

    Ok(ipt)
}

fn clean_iptables(ipt: IPTables, protected_port: String) -> Result<()> {
    ipt.delete(
        "filter",
        "INPUT",
        format!(
            "-p udp --match multiport --dports {} -j {}",
            protected_port, IPTABLES_CHAIN
        )
        .as_str(),
    )
    .unwrap();
    ipt.flush_chain("filter", IPTABLES_CHAIN).unwrap();
    ipt.delete_chain("filter", IPTABLES_CHAIN).unwrap();
    Ok(())
}

async fn shutdown_signal(
    ipt: IPTables,
    protected_port: String,
    ipset_session: Arc<Mutex<Session<HashIp>>>,
) {
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

    tokio::select! {
        _ = ctrl_c => {
            clean_iptables(ipt,protected_port).unwrap();
            clean_ipset(ipset_session.lock().await.deref_mut()).unwrap();
        },
        _ = terminate => {
            clean_iptables(ipt,protected_port).unwrap();
            clean_ipset(ipset_session.lock().await.deref_mut()).unwrap();
        },
    }
}

#[tokio::main]
async fn main() {
    let arg = Args::parse();
    // let mut session: Session<HashIp> = Session::<HashIp>::new("gmad-whitelist".to_string());
    let ipset_session = setup_ipset().unwrap();

    let protected_port = arg.protect.clone();

    let iptables = setup_iptables(protected_port).unwrap();

    let arc_ipset_session = Arc::new(Mutex::new(ipset_session));
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/", any(handler))
        .route("/{*key}", any(handler))
        .layer((
            TraceLayer::new_for_http(),
            // Graceful shutdown will wait for outstanding requests to complete. Add a timeout so
            // requests don't hang forever.
            TimeoutLayer::new(Duration::from_secs(10)),
        ))
        .with_state(arc_ipset_session.clone());

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", arg.listen.to_string()))
        .await
        .unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(
        iptables,
        arg.protect,
        arc_ipset_session.clone(),
    ))
    .await
    .unwrap();
}
