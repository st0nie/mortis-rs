use std::error::Error;

use anyhow::Result;
use ipset::{types::HashIp, Session};
use iptables::IPTables;

const IPTABLES_CHAIN: &str = "mortis";
const MORTIS_IPSET: &str = "mortis-whitelist";

pub fn setup_ipset() -> Result<Session<HashIp>> {
    let mut session: Session<HashIp> = Session::<HashIp>::new(MORTIS_IPSET.to_string());
    session.create(|builder| {
        builder
            .with_ipv6(false)?
            // .with_timeout(300)?
            .with_forceadd()?
            .build()
    })?;

    Ok(session)
}

pub fn clean_ipset(ipset_session: &mut Session<HashIp>) -> Result<()> {
    ipset_session.flush()?;
    ipset_session.destroy()?;
    Ok(())
}

pub fn setup_iptables(protected_port: &str) -> Result<IPTables, Box<dyn Error>> {
    let ipt = iptables::new(false)?;
    ipt.new_chain("filter", IPTABLES_CHAIN)?;

    ipt.append(
        "filter",
        IPTABLES_CHAIN,
        "-p udp --match multiport --sports 123,53,161,3702,19 -j DROP",
    )?;
    ipt.append(
        "filter",
        IPTABLES_CHAIN,
        format!(
            "--match set --match-set {} src --match hashlimit --hashlimit-above 150/sec --hashlimit-burst 10 --hashlimit-mode srcip,dstport --hashlimit-name mortis-white -j DROP",
            MORTIS_IPSET.to_string()
        )
        .as_str(),
    )?;
    ipt.append(
        "filter",
        IPTABLES_CHAIN,
        format!(
            "--match set --match-set {} src -j RETURN",
            MORTIS_IPSET.to_string()
        )
        .as_str(),
    )?;
    ipt.append("filter", IPTABLES_CHAIN,  "--match hashlimit --hashlimit-above 5/sec --hashlimit-burst 10 --hashlimit-mode srcip,dstport --hashlimit-name mortis -j DROP")?;
    ipt.append("filter", IPTABLES_CHAIN, "-j RETURN")?;
    ipt.insert(
        "filter",
        "INPUT",
        format!(
            "-p udp --match multiport --dports {} -j {}",
            protected_port, IPTABLES_CHAIN,
        )
        .as_str(),
        1,
    )?;

    Ok(ipt)
}

pub fn clean_iptables(ipt: &IPTables, protected_port: &str) -> Result<(), Box<dyn Error>> {
    ipt.delete(
        "filter",
        "INPUT",
        format!(
            "-p udp --match multiport --dports {} -j {}",
            protected_port, IPTABLES_CHAIN
        )
        .as_str(),
    )?;
    ipt.flush_chain("filter", IPTABLES_CHAIN)?;
    ipt.delete_chain("filter", IPTABLES_CHAIN)?;
    Ok(())
}
