use crate::{config::Config, wire};
use axum::Router;
use std::{net::SocketAddr, sync::Arc};

pub(crate) async fn router(_config: Arc<Config>, _address: SocketAddr) -> anyhow::Result<Router> {
    Ok(wire::unimplemented_router(false))
}
