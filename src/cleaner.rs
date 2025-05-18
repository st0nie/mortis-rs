use std::{ops::DerefMut, sync::Arc, time::Duration};

use anyhow::{Ok, Result};
use tokio::{sync::Mutex, time::MissedTickBehavior};

use crate::state::AppState;

pub async fn task(state: Arc<AppState>) {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        {
            let _ = clean_ipset(state.clone()).await;
        }
    }
}

async fn clean_ipset(state: Arc<AppState>) -> Result<()> {
    let mut whitelist = state.whitelist.lock().await;
    let mut ipset_session = state.ipset_session.lock().await;
    let ipset = ipset_session.deref_mut();

    let mut to_remove = Vec::new();

    for (ip, instant) in whitelist.iter() {
        if instant.elapsed().as_secs() > 300 {
            to_remove.push(*ip);
        }
    }

    to_remove.iter().try_for_each(|ip| {
        whitelist.remove(ip);
        ipset.del(*ip)?;
        Ok(())
    })?;

    Ok(())
}
