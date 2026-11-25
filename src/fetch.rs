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
    let mut native_operations = std::collections::HashSet::new();
    while let Some(req) = fetch_rx.recv().await {
        if let FetchRequest::ApplyMikroTik(preview) = &req {
            if !native_operations.insert(preview.operation) {
                continue;
            }
        }
        let req = match req {
            FetchRequest::UpdateNativeRegistration(config) => {
                ssh.register_router(config).await;
                continue;
            }
            FetchRequest::RemoveNativeRegistration(id) => {
                ssh.unregister_router(id).await;
                continue;
            }
            ordinary => ordinary,
        };
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
        FetchRequest::ApplyMikroTik(preview) => {
            // Getting config does not authorize a new token: the backend always
            // acquires the ORIGINAL preview registration, including after queueing.
            let receipt = match ssh.get_config(preview.router_id).await {
                Some(config) => {
                    crate::router::mikrotik::MikroTikBackend::new(&config, Arc::clone(&ssh))
                        .apply(preview)
                        .await
                }
                None => crate::router::mikrotik::rejected_receipt(&preview),
            };
            let _ = tx.send(AppEvent::MikroTikApplied(receipt));
        }
        FetchRequest::UpdateNativeRegistration(_) | FetchRequest::RemoveNativeRegistration(_) => {
            // These controls are handled inline by the receive loop, never spawned.
        }
        FetchRequest::RefreshMikroTik {
            router_id,
            request,
            instance,
        } => {
            let (config, registration) = match ssh.registered_snapshot(router_id).await {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    publish_native_refresh_result(&tx, router_id, request, Err(error));
                    return;
                }
            };
            if config.vendor != RouterVendor::MikroTik {
                publish_native_refresh_result(
                    &tx,
                    router_id,
                    request,
                    Err(anyhow::anyhow!("native vendor changed")),
                );
                return;
            }
            let backend = crate::router::mikrotik::MikroTikBackend::new_registered(
                &config,
                registration,
                Arc::clone(&ssh),
            );
            let result = backend.discover(request, instance.as_deref()).await;
            publish_native_refresh_result(&tx, router_id, request, result);
        }
        FetchRequest::FetchNativeRoutes { request, source } => {
            let result = native_peer_routes(&ssh, &request, &source).await;
            let _ = tx.send(AppEvent::NativeRoutes(request, result));
        }
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
            history_action,
            commands,
            description,
            ..
        } => {
            if crate::db::ConfigHistoryEntry::is_native_receipt_action(&history_action) {
                let _ = tx.send(AppEvent::ConfigError {
                    router_id,
                    description: "Native history replay rejected".into(),
                    error: "MikroTik receipt is non-replayable; create a fresh reviewed operation"
                        .into(),
                });
                return;
            }
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

#[derive(Clone, Copy)]
enum NativeReadFailure {
    UnsupportedVersion,
    InstanceSelection,
    ScopeUnusable,
    Capability,
    Transport,
    RegistrationChanged,
    Unclassified,
}

impl NativeReadFailure {
    fn from_code(code: &str) -> Self {
        match code {
            "stale-native-registration" => Self::RegistrationChanged,
            "spawn" | "process" | "stdout-pipe" | "stderr-pipe" | "stdout-read" | "stderr"
            | "exit-status" | "wait" | "timeout" | "output-budget" => Self::Transport,
            "invalid-envelope" | "request-mismatch" | "command-rejected" | "decode-worker" => {
                Self::Capability
            }
            _ => Self::Unclassified,
        }
    }

    fn classify(error: &anyhow::Error) -> Self {
        if let Some(error) = error.downcast_ref::<crate::ssh::NativeExecError>() {
            return Self::from_code(error.code);
        }
        if let Some(error) = error.downcast_ref::<crate::router::mikrotik::NativeWireError>() {
            return Self::from_code(error.code);
        }
        // The completed reader uses literal client error/context messages.
        // Downcast them, never Display/Debug arbitrary error chains or compare
        // substring matches against potentially credential-bearing device text.
        match error.downcast_ref::<&'static str>().copied() {
            Some("unsupported RouterOS version; requires 7.24.7" | "native inventory is unsupported") => Self::UnsupportedVersion,
            Some("an existing BGP instance must be explicitly selected"
                | "selected native instance is unavailable; explicitly select an existing main instance"
                | "selected native instance is unavailable") => Self::InstanceSelection,
            Some("selected native instance is not effective main"
                | "selected native instance is unusable or state is unknown"
                | "selected native instance is unusable"
                | "native instance state is unreadable"
                | "selected instance VRF is not main"
                | "selected instance routing table is not main"
                | "cannot guard selected native instance") => Self::ScopeUnusable,
            Some("native installed version is unavailable"
                | "cannot decode native inventory"
                | "cannot decode native reference inventory"
                | "invalid native record collection"
                | "unexpected sensitive native property"
                | "missing or invalid native identity/scope field"
                | "invalid or missing required native configuration field") => Self::Capability,
            Some("stale-native-registration" | "native vendor changed"
                | "native backend configuration changed" | "native registration decision mismatch"
                | "native selected scope changed" | "cannot resolve native registration"
                | "cannot acquire native read lease") => Self::RegistrationChanged,
            _ => Self::Unclassified,
        }
    }

    fn category(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "unsupported-version",
            Self::InstanceSelection => "instance-selection",
            Self::ScopeUnusable => "scope-unusable",
            Self::Capability => "capability",
            Self::Transport => "transport",
            Self::RegistrationChanged => "registration-changed",
            Self::Unclassified => "unclassified",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "[unsupported-version] Unsupported RouterOS version; use RouterOS 7.24.7 before refreshing.",
            Self::InstanceSelection => "[instance-selection] Selected BGP Instance is missing or renamed; choose an existing main-table instance in router settings.",
            Self::ScopeUnusable => "[scope-unusable] Selected BGP Instance is non-main, disabled, inactive or unreadable; select an observable, usable main-table instance.",
            Self::Capability => "[capability] Native JSON/inventory read is unavailable or invalid; check read permissions and RouterOS 7.24.7 compatibility.",
            Self::Transport => "[transport] Native SSH read failed or exceeded client limits; check connectivity, authentication and device load, then retry.",
            Self::RegistrationChanged => "[registration-changed] Router registration or selection changed; check the current router entry and refresh again.",
            Self::Unclassified => "[unclassified] Native read failed; check the router entry and read permissions, then refresh again.",
        }
    }
}

fn publish_native_refresh_result(
    tx: &mpsc::UnboundedSender<AppEvent>,
    router_id: Uuid,
    request: Uuid,
    result: anyhow::Result<crate::router::mikrotik::NativeDiscovery>,
) {
    match result {
        Ok(discovery) => {
            let _ = tx.send(AppEvent::NativeData(
                router_id,
                request,
                Box::new(discovery),
            ));
        }
        Err(error) => {
            let failure = NativeReadFailure::classify(&error);
            tracing::warn!(router_id = %router_id, request = %request,
                category = %failure.category(), "native refresh failed");
            let _ = tx.send(AppEvent::NativeError(
                router_id,
                request,
                failure.message().into(),
            ));
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
            RouterVendor::MikroTik => {
                let _ = tx.send(AppEvent::NativeError(
                    id,
                    Uuid::nil(),
                    "MikroTik requires a tracked native request".into(),
                ));
                return;
            }
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
            RouterVendor::Cumulus => {
                let mut b = crate::router::cumulus::CumulusBackend::new(&cfg, Arc::clone(ssh));
                match b.refresh().await {
                    Ok(s) => Ok((s, b.get_routes().await.unwrap_or_default())),
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
                RouterVendor::MikroTik => return,
                RouterVendor::Cisco | RouterVendor::VyOs | RouterVendor::Cumulus => {
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
        RouterVendor::MikroTik => return,
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
        RouterVendor::Cumulus => {
            crate::router::cumulus::CumulusBackend::new(&cfg, Arc::clone(ssh))
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
    ip: String,
    dir: PeerRouteDirection,
) {
    let cfg = match ssh.get_config(router_id).await {
        Some(c) => c,
        None => return,
    };

    let start = Instant::now();
    tracing::debug!(router = %cfg.name, peer = %ip, direction = %dir.label(), "fetching peer routes");

    let address = ip.parse::<IpAddr>();
    let result = match cfg.vendor {
        RouterVendor::MikroTik => Err(anyhow::anyhow!("MikroTik requires native peer identity")),
        RouterVendor::Cisco => match address {
            Ok(ip) => {
                CiscoBackend::new(&cfg, Arc::clone(ssh))
                    .get_peer_routes(ip, dir)
                    .await
            }
            Err(e) => Err(e.into()),
        },
        RouterVendor::VyOs => match address {
            Ok(ip) => {
                crate::router::vyos::VyOsBackend::new(&cfg, Arc::clone(ssh))
                    .get_peer_routes(ip, dir)
                    .await
            }
            Err(e) => Err(e.into()),
        },
        RouterVendor::Cumulus => {
            crate::router::cumulus::CumulusBackend::new(&cfg, Arc::clone(ssh))
                .get_peer_routes(&ip, dir)
                .await
        }
        RouterVendor::CitrixVpx => match address {
            Ok(ip) => {
                crate::router::citrix::CitrixVpxBackend::new(&cfg, Arc::clone(ssh))
                    .get_peer_routes(ip, dir)
                    .await
            }
            Err(e) => Err(e.into()),
        },
        RouterVendor::PfSense => match address {
            Ok(ip) => {
                crate::router::pfsense::PfSenseBackend::new(&cfg, Arc::clone(ssh))
                    .get_peer_routes(ip, dir)
                    .await
            }
            Err(e) => Err(e.into()),
        },
        RouterVendor::FortiGate => match address {
            Ok(ip) => {
                crate::router::fortigate::FortiGateBackend::new(&cfg, Arc::clone(ssh))
                    .get_peer_routes(ip, dir)
                    .await
            }
            Err(e) => Err(e.into()),
        },
        RouterVendor::A10 => match address {
            Ok(ip) => {
                crate::router::a10::A10Backend::new(&cfg, Arc::clone(ssh))
                    .get_peer_routes(ip, dir)
                    .await
            }
            Err(e) => Err(e.into()),
        },
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
        RouterVendor::MikroTik => Err(anyhow::anyhow!(
            "MikroTik MTU unavailable; no native probes"
        )),
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
        RouterVendor::Cumulus => {
            crate::router::cumulus::CumulusBackend::new(&cfg, Arc::clone(ssh))
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
        RouterVendor::MikroTik => Err(anyhow::anyhow!(
            "MikroTik native management unavailable; raw CLI rejected"
        )),
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
        RouterVendor::Cumulus => {
            crate::router::cumulus::CumulusBackend::new(&cfg, Arc::clone(ssh))
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

async fn native_peer_routes(
    ssh: &Arc<SshSessionManager>,
    request: &crate::app::NativeRouteRequest,
    source: &crate::router::mikrotik::MikroTikSnapshot,
) -> crate::router::mikrotik::NativeRead<Vec<crate::bgp::BgpRoute>> {
    use crate::router::mikrotik::NativeRead;
    let result = async {
        anyhow::ensure!(
            request.router_id == source.router_id
                && request.generation == source.generation
                && request.registration == source.registration,
            "native displayed source mismatch"
        );
        anyhow::ensure!(
            request.direction == PeerRouteDirection::Received,
            "native advertisements unavailable"
        );
        // Check the original token, not a newly looked-up registration. Even
        // cached drill-down cannot be attributed to a replacement endpoint.
        let _lease = ssh.native_lease(&request.registration).await?;
        crate::app::native_stored_peer_routes(source, &request.peer)
    }
    .await;
    match result {
        Ok(routes) => NativeRead::Available(routes),
        Err(_) => NativeRead::Unavailable("Native stored routes unavailable: stale source, scope or association (not full Adj-RIB-In)".into()),
    }
}

#[cfg(test)]
mod native_tests {
    use super::*;
    use crate::app::NativeRouteRequest;
    use crate::bgp::PeerKey;
    use crate::router::mikrotik::{test_support::documented_snapshot, NativeRead};

    #[tokio::test]
    async fn mikrotik_receipt_service_rejects_native_provenance_after_vendor_change() {
        let cfg = crate::router::RouterConfig {
            vendor: RouterVendor::Cisco,
            ..crate::router::RouterConfig::default()
        };
        let ssh = SshSessionManager::new(&[cfg.clone()]);
        let (tx, mut rx) = mpsc::unbounded_channel();
        handle_request(
            ssh,
            tx,
            FetchRequest::RollbackConfig {
                router_id: cfg.id,
                history_id: Uuid::new_v4(),
                history_action: "mikrotik_receipt:Indeterminate".into(),
                commands: vec!["forged executable".into()],
                description: "test".into(),
            },
        )
        .await;
        assert!(
            matches!(rx.try_recv().unwrap(),AppEvent::ConfigError{error,..} if error.contains("non-replayable"))
        );
    }

    #[tokio::test]
    async fn mikrotik_apply_service_duplicate_operation_is_ignored_not_replayed() {
        use crate::router::mikrotik::{preview_native, NativeIntent};
        let cfg = crate::router::RouterConfig {
            id: Uuid::nil(),
            vendor: RouterVendor::Cisco,
            ..crate::router::RouterConfig::default()
        };
        let manager = SshSessionManager::new(&[cfg]);
        let snapshot = documented_snapshot();
        let operation = Uuid::new_v4();
        let (fetch_tx, fetch_rx) = mpsc::unbounded_channel();
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        for _ in 0..2 {
            let preview = preview_native(
                &snapshot,
                NativeIntent::Delete(snapshot.peers[0].connection.clone().unwrap()),
                operation,
            )
            .unwrap();
            assert!(fetch_tx.send(FetchRequest::ApplyMikroTik(preview)).is_ok());
        }
        drop(fetch_tx);
        run_data_fetch_service(manager, event_tx, fetch_rx).await;
        let mut receipts = 0;
        while let Some(event) = event_rx.recv().await {
            if let AppEvent::MikroTikApplied(receipt) = event {
                assert_eq!(receipt.operation, operation);
                receipts += 1;
            }
        }
        assert_eq!(receipts, 1);
    }
    use crate::router::RouterConfig;

    fn config() -> RouterConfig {
        RouterConfig {
            id: Uuid::nil(),
            vendor: RouterVendor::MikroTik,
            hostname: "lab.invalid".into(),
            username: "tester".into(),
            mikrotik_instance: Some("blue".into()),
            ..RouterConfig::default()
        }
    }

    fn native_error_event(
        result: anyhow::Result<crate::router::mikrotik::NativeDiscovery>,
    ) -> String {
        let request = Uuid::new_v4();
        let (tx, mut rx) = mpsc::unbounded_channel();
        publish_native_refresh_result(&tx, Uuid::nil(), request, result);
        let AppEvent::NativeError(router_id, event_request, message) = rx.try_recv().unwrap()
        else {
            panic!("native service error event required")
        };
        assert_eq!(router_id, Uuid::nil());
        assert_eq!(event_request, request);
        assert!(rx.try_recv().is_err());
        message
    }

    #[tokio::test]
    async fn mikrotik_rev_002_service_reader_errors_keep_actionable_version_instance_and_scope_categories(
    ) {
        use crate::router::mikrotik::{fetch_native, test_support::*};
        use serde_json::json;
        let registration = documented_registration();
        let io = TranscriptExecutor::new(vec![Reply::Data(json!("7.24.6 (stable)"))]);
        let result = fetch_native(&io, &registration, Uuid::new_v4(), Some("blue")).await;
        let message = native_error_event(result);
        assert!(
            message.starts_with("[unsupported-version]"),
            "version failure category was lost"
        );
        assert!(message.contains("7.24.7"));
        assert_eq!(io.seen_labels().len(), 1);
        for renamed in [false, true] {
            let mut inventory = documented_inventory();
            if renamed {
                inventory.instances[0]
                    .props
                    .insert("name".into(), json!("renamed-blue"));
            } else {
                inventory.instances.clear();
            }
            let io = TranscriptExecutor::new(vec![
                Reply::Data(json!("7.24.7")),
                Reply::Data(serde_json::to_value(inventory.instances).unwrap()),
            ]);
            let result = fetch_native(&io, &registration, Uuid::new_v4(), Some("blue")).await;
            let message = native_error_event(result);
            assert!(
                message.starts_with("[instance-selection]"),
                "missing/renamed selection category was lost"
            );
            assert!(message.contains("router settings"));
            assert_eq!(io.seen_labels().len(), 2);
        }
        for (property, value) in [
            ("routing-table", json!("not-main")),
            ("disabled", json!(true)),
            ("inactive", json!("unknown-state")),
        ] {
            let mut inventory = documented_inventory();
            inventory.instances[0].props.insert(property.into(), value);
            let io = TranscriptExecutor::new(vec![
                Reply::Data(json!("7.24.7")),
                Reply::Data(serde_json::to_value(inventory.instances).unwrap()),
            ]);
            let result = fetch_native(&io, &registration, Uuid::new_v4(), Some("blue")).await;
            let message = native_error_event(result);
            assert!(
                message.starts_with("[scope-unusable]"),
                "non-main/unusable scope category was lost"
            );
            assert!(message.contains("main-table"));
            assert_eq!(io.mutation_attempts(), 0);
        }
    }

    #[tokio::test]
    async fn mikrotik_rev_002_service_reader_separates_known_transport_and_capability_failures() {
        use crate::router::mikrotik::{fetch_native, test_support::*};
        use serde_json::json;
        for (code, category) in [
            ("timeout", "[transport]"),
            ("spawn", "[transport]"),
            ("command-rejected", "[capability]"),
            ("invalid-envelope", "[capability]"),
        ] {
            let io = TranscriptExecutor::new(vec![Reply::Failure {
                code,
                started: true,
            }]);
            let message = native_error_event(
                fetch_native(
                    &io,
                    &documented_registration(),
                    Uuid::new_v4(),
                    Some("blue"),
                )
                .await,
            );
            assert!(
                message.starts_with(category),
                "recognized native execution failure was not classified"
            );
            assert_eq!(io.mutation_attempts(), 0);
        }
        let io = TranscriptExecutor::new(vec![
            Reply::Data(json!("7.24.7")),
            Reply::Data(json!("synthetic-device-credential")),
        ]);
        let message = native_error_event(
            fetch_native(
                &io,
                &documented_registration(),
                Uuid::new_v4(),
                Some("blue"),
            )
            .await,
        );
        assert!(message.starts_with("[capability]"));
        assert!(!message.contains("synthetic-device-credential"));
    }

    #[derive(Clone)]
    struct NativeLogWriter(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for NativeLogWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct UntrustedNativeError(Arc<std::sync::atomic::AtomicUsize>);

    impl std::fmt::Display for UntrustedNativeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            f.write_str("synthetic-password-never-format")
        }
    }
    impl std::error::Error for UntrustedNativeError {}

    #[test]
    fn mikrotik_rev_002_service_unknown_errors_are_redacted_without_formatting_or_payload_logging()
    {
        let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = NativeLogWriter(Arc::clone(&bytes));
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let formatted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for error in [
            anyhow::Error::new(UntrustedNativeError(Arc::clone(&formatted)))
                .context("synthetic-credential-context"),
            anyhow::anyhow!(
                "device says unsupported RouterOS version; requires 7.24.7 synthetic-credential"
            ),
            anyhow::Error::new(crate::ssh::NativeExecError {
                code: "timeout synthetic-credential",
                started: true,
            }),
        ] {
            let message = native_error_event(Err(error));
            assert!(message.starts_with("[unclassified]"));
            assert!(!message.contains("synthetic-credential"));
            assert!(!message.contains("synthetic-password"));
        }
        assert_eq!(
            formatted.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "unknown error chains must never be formatted even for classification"
        );
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert!(
            output.contains("unclassified"),
            "safe diagnostic category must be retained"
        );
        assert!(!output.contains("synthetic-credential"));
        assert!(!output.contains("synthetic-password"));
    }

    #[tokio::test]
    async fn mikrotik_rev_002_service_success_and_stale_registration_keep_typed_event_path() {
        use crate::router::mikrotik::{fetch_native, test_support::*, NativeDiscovery};
        let request = Uuid::new_v4();
        let io = TranscriptExecutor::new(vec![
            Reply::Data(serde_json::json!("7.24.7")),
            Reply::Data(serde_json::to_value(documented_inventory().instances).unwrap()),
        ]);
        let result = fetch_native(&io, &documented_registration(), request, None).await;
        let (tx, mut rx) = mpsc::unbounded_channel();
        publish_native_refresh_result(&tx, Uuid::nil(), request, result);
        let AppEvent::NativeData(id, event_request, discovery) = rx.try_recv().unwrap() else {
            panic!("typed discovery success")
        };
        assert_eq!(id, Uuid::nil());
        assert_eq!(event_request, request);
        assert!(
            matches!(*discovery, NativeDiscovery::Instances { names, .. } if names == vec!["blue"])
        );
        let ssh = SshSessionManager::new(&[]);
        handle_request(
            ssh,
            tx,
            FetchRequest::RefreshMikroTik {
                router_id: Uuid::nil(),
                request,
                instance: Some("blue".into()),
            },
        )
        .await;
        assert!(
            matches!(rx.try_recv().unwrap(), AppEvent::NativeError(_, event_request, message)
            if event_request == request && message.starts_with("[registration-changed]"))
        );
    }

    #[tokio::test]
    async fn mikrotik_cache_service_processes_registration_controls_inline_in_order() {
        let ssh = SshSessionManager::new(&[]);
        let (events, mut event_rx) = mpsc::unbounded_channel();
        let (tx, rx) = mpsc::unbounded_channel();
        let service = tokio::spawn(run_data_fetch_service(Arc::clone(&ssh), events, rx));
        tx.send(FetchRequest::UpdateNativeRegistration(config()))
            .unwrap();
        // Generic refresh must see the registration just received and reject
        // before any transport. If control handling were spawned it could race.
        tx.send(FetchRequest::RefreshRouter(Uuid::nil())).unwrap();
        let event = tokio::time::timeout(std::time::Duration::from_secs(2), event_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(event, AppEvent::NativeError(id, request, _) if id.is_nil() && request.is_nil())
        );
        assert_eq!(
            ssh.get_config(Uuid::nil()).await.unwrap().vendor,
            RouterVendor::MikroTik
        );
        tx.send(FetchRequest::RemoveNativeRegistration(Uuid::nil()))
            .unwrap();
        drop(tx);
        service.await.unwrap();
        assert!(ssh.get_config(Uuid::nil()).await.is_none());
    }

    #[tokio::test]
    async fn mikrotik_cache_native_drilldown_pins_source_identity_generation_and_registration() {
        let config = config();
        let ssh = SshSessionManager::new(&[config.clone()]);
        let mut snapshot = documented_snapshot();
        snapshot.registration = ssh.native_registration(config.id).await.unwrap();
        let request = NativeRouteRequest {
            router_id: config.id,
            request: Uuid::new_v4(),
            registration: snapshot.registration.clone(),
            generation: snapshot.generation,
            peer: PeerKey::RouterOsConnection {
                instance: "blue".into(),
                name: "peer-a".into(),
            },
            direction: PeerRouteDirection::Received,
        };
        let NativeRead::Available(routes) = native_peer_routes(&ssh, &request, &snapshot).await
        else {
            panic!("known stored routes")
        };
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].as_path_str(), "65001,{65002,65003}");
        let mut forged = request.clone();
        forged.generation = Uuid::new_v4();
        assert!(matches!(
            native_peer_routes(&ssh, &forged, &snapshot).await,
            NativeRead::Unavailable(_)
        ));
        let mut recreated = snapshot.clone();
        recreated.peers[0].record.id = "*NEW".into();
        assert!(matches!(
            native_peer_routes(&ssh, &request, &recreated).await,
            NativeRead::Unavailable(_)
        ));
        let mut replacement = config;
        replacement.hostname = "replacement.invalid".into();
        ssh.register_router(replacement).await;
        assert!(matches!(
            native_peer_routes(&ssh, &request, &snapshot).await,
            NativeRead::Unavailable(_)
        ));
    }

    #[tokio::test]
    async fn mikrotik_management_generic_io_is_rejected_without_transport() {
        let config = config();
        let ssh = SshSessionManager::new(&[config.clone()]);
        let (tx, mut rx) = mpsc::unbounded_channel();
        for request in [
            FetchRequest::FetchPeerRoutes {
                router_id: config.id,
                ip: "192.0.2.2".into(),
                dir: PeerRouteDirection::Received,
            },
            FetchRequest::FetchMtu {
                router_id: config.id,
                target: "192.0.2.2".parse().unwrap(),
            },
            FetchRequest::ApplyConfig {
                router_id: config.id,
                commands: vec!["synthetic-sensitive-command".into()],
                description: "test".into(),
            },
            FetchRequest::RollbackConfig {
                router_id: config.id,
                history_id: Uuid::new_v4(),
                history_action: "legacy-create".into(),
                commands: vec!["synthetic-sensitive-command".into()],
                description: "test".into(),
            },
        ] {
            handle_request(Arc::clone(&ssh), tx.clone(), request).await;
        }
        assert!(
            matches!(rx.try_recv().unwrap(), AppEvent::PeerRoutesError(_, _, _, error) if error.contains("native peer"))
        );
        assert!(
            matches!(rx.try_recv().unwrap(), AppEvent::MtuProbeError(_, _, error) if error.contains("unavailable"))
        );
        assert!(
            matches!(rx.try_recv().unwrap(), AppEvent::ConfigError { error, .. } if error.contains("raw CLI rejected") && !error.contains("synthetic-sensitive-command"))
        );
        assert!(
            matches!(rx.try_recv().unwrap(),AppEvent::ConfigError {error,..} if error.contains("raw CLI rejected"))
        );
        handle_request(
            Arc::clone(&ssh),
            tx,
            FetchRequest::FetchRouteMap {
                router_id: config.id,
                rm_name: "native-chain".into(),
            },
        )
        .await;
        assert!(rx.try_recv().is_err());
        let mut backend = crate::router::RouterBackend::MikroTik(
            crate::router::mikrotik::MikroTikBackend::new(&config, ssh),
        );
        assert!(backend.apply_config("raw commands").await.is_err());
        assert!(backend.refresh().await.is_err());
        assert!(backend.get_routes().await.is_err());
    }
}
