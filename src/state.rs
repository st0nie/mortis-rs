use std::{
    collections::HashMap, net::IpAddr,
};

use tokio::{sync::Mutex, time::Instant};

use crate::Args;

pub struct AppState {
    pub iptables: iptables::IPTables,
    pub ipset_session: Mutex<ipset::Session<ipset::types::HashIp>>,
    pub args: Args,

    pub whitelist: Mutex<HashMap<IpAddr, Instant>>,
}