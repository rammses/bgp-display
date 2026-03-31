use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::bgp::PeerRouteDirection;
use crate::events::{AppEvent, FetchRequest};
use crate::logging::thresholds;
use crate::router::cisco::CiscoBackend;
use crate::router::RouterVendor;
use crate::ssh::SshSessionManager;

/// Background worker that processes [`FetchRequest`] messages and sends
/// results back to the UI via [`AppEvent`].
///
/// Started once in [`crate::tui::run_tui`].  Runs until the receiver is
/// dropped (application exit).
pub async fn run_data_fetch_service(
    ssh: Arc<SshSessionManager>,
    event_tx: mpsc::UnboundedSender<AppEvent>,
    mut fetch_rx: mpsc::UnboundedReceiver<FetchRequest>,
) {
    tracing::info!("data fetch service started");
    while let Some(req) = fetch_rx.recv().await {
        let ssh = Arc::clone(&ssh);
        let tx = event_tx.clone();
        tokio::spawn(async move {
            handle_request(ssh, tx, req).await;
        });
    }
    tracing::info!("data fetch service stopped");
}

async fn handle_request(
    ssh: Arc<SshSessionManager>,
    tx: mpsc::UnboundedSender<AppEvent>,
    req: FetchRequest,
) {
    match req {
        FetchRequest::RefreshRouter(id) => {
            refresh_router(&ssh, &tx, id).await;
        }
        FetchRequest::RefreshMany(ids) => {
            let count = ids.len();
            tracing::info!(count, "refresh many routers");
            for id in ids {
                let ssh = Arc::clone(&ssh);
                let tx = tx.clone();
                tokio::spawn(async move {
                    refresh_router(&ssh, &tx, id).await;
                });
            }
        }
        FetchRequest::FetchRouteMap { router_id, rm_name } => {
            fetch_route_map(&ssh, &tx, router_id, &rm_name).await;
        }
        FetchRequest::FetchPeerRoutes { router_id, ip, dir } => {
            fetch_peer_routes(&ssh, &tx, router_id, ip, dir).await;
        }
        FetchRequest::FetchMtu { router_id, target } => {
            fetch_mtu(&ssh, &tx, router_id, target).await;
        }
        FetchRequest::ApplyConfig {
            router_id,
            commands,
            description,
        } => {
            apply_config(&ssh, &tx, router_id, &commands, &description).await;
        }
        FetchRequest::RollbackConfig {
            router_id,
            commands,
            description,
            ..
        } => {
            apply_config(&ssh, &tx, router_id, &commands, &description).await;
        }
        FetchRequest::Ping(targets) => {
            let count = targets.len();
            tracing::debug!(count, "ping targets");
            for (id, addr) in targets {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let start = std::time::Instant::now();
                    let rtt = match tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        tokio::net::TcpStream::connect(&addr),
                    )
                    .await
                    {
                        Ok(Ok(_)) => Some(start.elapsed()),
                        _ => None,
                    };
                    let _ = tx.send(AppEvent::PingResult(id, rtt));
                });
            }
        }
    }
}

// ─── Vendor-dispatched operations ───────────────────────────────────────────

async fn refresh_router(
    ssh: &Arc<SshSessionManager>,
    tx: &mpsc::UnboundedSender<AppEvent>,
    id: Uuid,
) {
    let cfg = match ssh.get_config(id).await {
        Some(c) => c,
        None => {
            tracing::warn!(id = %id, "refresh_router: router not registered in SSH manager");
            return;
        }
    };

    let start = Instant::now();
    tracing::info!(router = %cfg.name, vendor = %cfg.vendor, "refreshing router");

    let result: anyhow::Result<(crate::bgp::BgpSummary, Vec<crate::bgp::BgpRoute>)> =
        match cfg.vendor {
            RouterVendor::Cisco => {
                let mut b = CiscoBackend::new(&cfg, Arc::clone(ssh));
                match b.refresh().await {
                    Ok(s) => {
                        let r = b.get_routes().await.unwrap_or_default();
                        Ok((s, r))
                    }
                    Err(e) => Err(e),
                }
            }
            RouterVendor::VyOs => {
                let mut b = crate::router::vyos::VyOsBackend::new(&cfg, Arc::clone(ssh));
                match b.refresh().await {
                    Ok(s) => {
                        let r = b.get_routes().await.unwrap_or_default();
                        Ok((s, r))
                    }
                    Err(e) => Err(e),
                }
            }
            RouterVendor::CitrixVpx => {
                let mut b = crate::router::citrix::CitrixVpxBackend::new(&cfg, Arc::clone(ssh));
                match b.refresh().await {
                    Ok(s) => {
                        let r = b.get_routes().await.unwrap_or_default();
                        Ok((s, r))
                    }
                    Err(e) => Err(e),
                }
            }
            RouterVendor::PfSense => {
                let mut b = crate::router::pfsense::PfSenseBackend::new(&cfg, Arc::clone(ssh));
                match b.refresh().await {
                    Ok(s) => {
                        let r = b.get_routes().await.unwrap_or_default();
                        Ok((s, r))
                    }
                    Err(e) => Err(e),
                }
            }
            RouterVendor::FortiGate => {
                let mut b = crate::router::fortigate::FortiGateBackend::new(&cfg, Arc::clone(ssh));
                match b.refresh().await {
                    Ok(s) => {
                        let r = b.get_routes().await.unwrap_or_default();
                        Ok((s, r))
                    }
                    Err(e) => Err(e),
                }
            }
            RouterVendor::A10 => {
                let mut b = crate::router::a10::A10Backend::new(&cfg, Arc::clone(ssh));
                match b.refresh().await {
                    Ok(s) => {
                        let r = b.get_routes().await.unwrap_or_default();
                        Ok((s, r))
                    }
                    Err(e) => Err(e),
                }
            }
        };

    let elapsed_us = start.elapsed().as_micros();
    let elapsed_ms = elapsed_us / 1000;

    match result {
        Ok((summary, routes)) => {
            let peers = summary.peers.len();
            let route_count = routes.len();
            if elapsed_us > thresholds::FETCH_WARN_US {
                tracing::warn!(
                    router = %cfg.name, peers, routes = route_count,
                    elapsed_ms, "router refresh SLOW"
                );
            } else {
                tracing::info!(
                    router = %cfg.name, peers, routes = route_count,
                    elapsed_ms, "router refresh OK"
                );
            }
            let mut rendered = CiscoBackend::render_bgp_stanza(&summary);

            // Fetch prefix-list and community-list definitions so they appear
            // on the Config tab and can be edited with 'e'.
            match cfg.vendor {
                RouterVendor::Cisco | RouterVendor::VyOs => {
                    let b = CiscoBackend::new(&cfg, Arc::clone(ssh));
                    let policy = b.fetch_policy_stanza().await;
                    if !policy.text.is_empty() {
                        rendered.push('\n');
                        rendered.push_str(&policy.text);
                    }
                    if !policy.prefix_lists.is_empty() || !policy.community_lists.is_empty() {
                        let _ = tx.send(AppEvent::PolicyData {
                            router_id: id,
                            prefix_lists: policy.prefix_lists,
                            community_lists: policy.community_lists,
                        });
                    }
                }
                _ => {}
            }

            let _ = tx.send(AppEvent::RouteData(id, routes));
            let _ = tx.send(AppEvent::BgpData(id, Box::new(summary), rendered));
        }
        Err(e) => {
            tracing::error!(
                router = %cfg.name, elapsed_ms,
                error = %e, "router refresh FAILED"
            );
            let _ = tx.send(AppEvent::BgpError(id, e.to_string()));
        }
    }
}

async fn fetch_route_map(
    ssh: &Arc<SshSessionManager>,
    tx: &mpsc::UnboundedSender<AppEvent>,
    router_id: Uuid,
    rm_name: &str,
) {
    let cfg = match ssh.get_config(router_id).await {
        Some(c) => c,
        None => return,
    };

    let start = Instant::now();
    tracing::debug!(router = %cfg.name, route_map = %rm_name, "fetching route-map detail");

    let detail = match cfg.vendor {
        RouterVendor::Cisco => {
            CiscoBackend::new(&cfg, Arc::clone(ssh))
                .fetch_route_map_detail(rm_name)
                .await
        }
        RouterVendor::VyOs => {
            crate::router::vyos::VyOsBackend::new(&cfg, Arc::clone(ssh))
                .fetch_route_map_detail(rm_name)
                .await
        }
        RouterVendor::CitrixVpx => {
            crate::router::citrix::CitrixVpxBackend::new(&cfg, Arc::clone(ssh))
                .fetch_route_map_detail(rm_name)
                .await
        }
        RouterVendor::PfSense => {
            crate::router::pfsense::PfSenseBackend::new(&cfg, Arc::clone(ssh))
                .fetch_route_map_detail(rm_name)
                .await
        }
        RouterVendor::FortiGate => {
            crate::router::fortigate::FortiGateBackend::new(&cfg, Arc::clone(ssh))
                .fetch_route_map_detail(rm_name)
                .await
        }
        RouterVendor::A10 => {
            crate::router::a10::A10Backend::new(&cfg, Arc::clone(ssh))
                .fetch_route_map_detail(rm_name)
                .await
        }
    };

    let elapsed_ms = start.elapsed().as_millis();
    match detail {
        Ok(detail) => {
            tracing::debug!(
                router = %cfg.name, route_map = %rm_name,
                elapsed_ms, "route-map detail fetched"
            );
            let _ = tx.send(AppEvent::RouteMapDetail(router_id, Box::new(detail)));
        }
        Err(e) => {
            tracing::warn!(
                router = %cfg.name, route_map = %rm_name,
                elapsed_ms, error = %e, "route-map detail fetch failed"
            );
        }
    }
}

async fn fetch_peer_routes(
    ssh: &Arc<SshSessionManager>,
    tx: &mpsc::UnboundedSender<AppEvent>,
    router_id: Uuid,
    ip: IpAddr,
    dir: PeerRouteDirection,
) {
    let cfg = match ssh.get_config(router_id).await {
        Some(c) => c,
        None => return,
    };

    let start = Instant::now();
    tracing::debug!(router = %cfg.name, peer = %ip, direction = %dir.label(), "fetching peer routes");

    let result = match cfg.vendor {
        RouterVendor::Cisco => {
            CiscoBackend::new(&cfg, Arc::clone(ssh))
                .get_peer_routes(ip, dir)
                .await
        }
        RouterVendor::VyOs => {
            crate::router::vyos::VyOsBackend::new(&cfg, Arc::clone(ssh))
                .get_peer_routes(ip, dir)
                .await
        }
        RouterVendor::CitrixVpx => {
            crate::router::citrix::CitrixVpxBackend::new(&cfg, Arc::clone(ssh))
                .get_peer_routes(ip, dir)
                .await
        }
        RouterVendor::PfSense => {
            crate::router::pfsense::PfSenseBackend::new(&cfg, Arc::clone(ssh))
                .get_peer_routes(ip, dir)
                .await
        }
        RouterVendor::FortiGate => {
            crate::router::fortigate::FortiGateBackend::new(&cfg, Arc::clone(ssh))
                .get_peer_routes(ip, dir)
                .await
        }
        RouterVendor::A10 => {
            crate::router::a10::A10Backend::new(&cfg, Arc::clone(ssh))
                .get_peer_routes(ip, dir)
                .await
        }
    };

    let elapsed_ms = start.elapsed().as_millis();
    match result {
        Ok(routes) => {
            tracing::debug!(
                router = %cfg.name, peer = %ip, direction = %dir.label(),
                routes = routes.len(), elapsed_ms, "peer routes fetched"
            );
            let _ = tx.send(AppEvent::PeerRoutes(router_id, ip, dir, routes));
        }
        Err(e) => {
            tracing::warn!(
                router = %cfg.name, peer = %ip, direction = %dir.label(),
                elapsed_ms, error = %e, "peer routes fetch failed"
            );
            let _ = tx.send(AppEvent::PeerRoutesError(router_id, ip, dir, e.to_string()));
        }
    }
}

async fn fetch_mtu(
    ssh: &Arc<SshSessionManager>,
    tx: &mpsc::UnboundedSender<AppEvent>,
    router_id: Uuid,
    target: IpAddr,
) {
    let cfg = match ssh.get_config(router_id).await {
        Some(c) => c,
        None => return,
    };

    let start = Instant::now();
    tracing::debug!(router = %cfg.name, target = %target, "running MTU probe");

    let result = match cfg.vendor {
        RouterVendor::Cisco => {
            CiscoBackend::new(&cfg, Arc::clone(ssh))
                .ping_mtu(target)
                .await
        }
        RouterVendor::VyOs => {
            crate::router::vyos::VyOsBackend::new(&cfg, Arc::clone(ssh))
                .ping_mtu(target)
                .await
        }
        RouterVendor::CitrixVpx => {
            crate::router::citrix::CitrixVpxBackend::new(&cfg, Arc::clone(ssh))
                .ping_mtu(target)
                .await
        }
        RouterVendor::PfSense => {
            crate::router::pfsense::PfSenseBackend::new(&cfg, Arc::clone(ssh))
                .ping_mtu(target)
                .await
        }
        RouterVendor::FortiGate => {
            crate::router::fortigate::FortiGateBackend::new(&cfg, Arc::clone(ssh))
                .ping_mtu(target)
                .await
        }
        RouterVendor::A10 => {
            crate::router::a10::A10Backend::new(&cfg, Arc::clone(ssh))
                .ping_mtu(target)
                .await
        }
    };

    let elapsed_ms = start.elapsed().as_millis();
    match result {
        Ok(bytes) => {
            tracing::info!(
                router = %cfg.name, target = %target,
                mtu = bytes, elapsed_ms, "MTU probe complete"
            );
            let _ = tx.send(AppEvent::MtuProbeResult(router_id, target, bytes));
        }
        Err(e) => {
            tracing::warn!(
                router = %cfg.name, target = %target,
                elapsed_ms, error = %e, "MTU probe failed"
            );
            let _ = tx.send(AppEvent::MtuProbeError(router_id, target, e.to_string()));
        }
    }
}

async fn apply_config(
    ssh: &Arc<SshSessionManager>,
    tx: &mpsc::UnboundedSender<AppEvent>,
    router_id: Uuid,
    commands: &[String],
    description: &str,
) {
    let cfg = match ssh.get_config(router_id).await {
        Some(c) => c,
        None => {
            let _ = tx.send(AppEvent::ConfigError {
                router_id,
                description: description.to_string(),
                error: "Router not registered in SSH manager".to_string(),
            });
            return;
        }
    };

    let start = Instant::now();
    tracing::info!(
        router = %cfg.name, vendor = %cfg.vendor,
        desc = %description, "applying config"
    );

    let result: anyhow::Result<()> = match cfg.vendor {
        RouterVendor::Cisco => {
            CiscoBackend::new(&cfg, Arc::clone(ssh))
                .write_config(commands)
                .await
        }
        RouterVendor::VyOs => {
            crate::router::vyos::VyOsBackend::new(&cfg, Arc::clone(ssh))
                .write_config(commands)
                .await
        }
        RouterVendor::CitrixVpx => {
            crate::router::citrix::CitrixVpxBackend::new(&cfg, Arc::clone(ssh))
                .write_config(commands)
                .await
        }
        RouterVendor::PfSense => {
            crate::router::pfsense::PfSenseBackend::new(&cfg, Arc::clone(ssh))
                .write_config(commands)
                .await
        }
        RouterVendor::FortiGate => {
            crate::router::fortigate::FortiGateBackend::new(&cfg, Arc::clone(ssh))
                .write_config(commands)
                .await
        }
        RouterVendor::A10 => {
            crate::router::a10::A10Backend::new(&cfg, Arc::clone(ssh))
                .write_config(commands)
                .await
        }
    };

    let elapsed_ms = start.elapsed().as_millis();
    match result {
        Ok(()) => {
            tracing::info!(
                router = %cfg.name, desc = %description,
                elapsed_ms, "config applied OK — triggering refresh"
            );
            let _ = tx.send(AppEvent::ConfigApplied {
                router_id,
                description: description.to_string(),
            });
            refresh_router(ssh, tx, router_id).await;
        }
        Err(e) => {
            tracing::error!(
                router = %cfg.name, desc = %description,
                elapsed_ms, error = %e, "config apply FAILED"
            );
            let _ = tx.send(AppEvent::ConfigError {
                router_id,
                description: description.to_string(),
                error: e.to_string(),
            });
        }
    }
}
