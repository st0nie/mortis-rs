use std::net::SocketAddr;

use warp::{filters::path::FullPath, Filter};

use clap::Parser;

use std::net::IpAddr;

use ipset::types::{Error, HashIp};
use ipset::Session;
use ipset::IPSet;


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
    path: FullPath,
    remote: Option<SocketAddr>,
) -> Result<impl warp::Reply, warp::Rejection> {
    Ok(warp::reply::html(format!(
        "Hello from path {:?} and remote {:?}",
        path.as_str(),
        remote
            .map(|r| r.ip().to_string())
            .unwrap_or("unknown".to_string())
    )))
}

#[tokio::main]
async fn main() {
    let arg = Args::parse();

    let filter = warp::any()
        .and(warp::path::full())
        .and(warp::filters::addr::remote())
        .and_then(handler);

    warp::serve(filter).run(([0,0,0,0], arg.listen)).await;
}
