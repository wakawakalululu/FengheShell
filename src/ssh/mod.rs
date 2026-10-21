#[path = "impls/connection.rs"]
mod connection;
#[path = "struct/mod.rs"]
mod structs;
pub(crate) use connection::{
    disconnect_ssh, inherit_automation_cancellation, network_stage, with_automation_cancellation,
    HandshakeHandler, HostKeyWait,
};
#[path = "impls/known_hosts.rs"]
pub(crate) mod known_hosts;
#[path = "impls/ppk.rs"]
pub(crate) mod ppk;
#[path = "impls/proxy.rs"]
pub(crate) mod proxy;
#[path = "impls/ssh.rs"]
mod ssh;
#[path = "impls/ssh_config.rs"]
pub(crate) mod ssh_config;

pub(crate) use ssh::*;
pub(crate) use structs::*;
