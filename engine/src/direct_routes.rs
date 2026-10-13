//! All-traffic mode's direct list: routes that send listed destinations
//! around the tunnel, through the physical gateway.
//!
//! Routes, because all-traffic mode never handles a packet it does not
//! carry: Windows decides where each one goes before the engine sees it, and
//! a route lets that decision stay in the kernel with no per-packet cost. A
//! connection keeps the path it opened on. Windows sends with the strong host
//! model, so a socket bound to the tunnel's address only leaves through the
//! tunnel; a route added later changes new connections, never live ones.
//!
//! Direct names become routes as their answers arrive. Answers that come back
//! through this tunnel are learned before the reply is delivered, so the
//! application's first connection already takes the route. Answers that come
//! back another way (the game's tunnel, which owns shared Windows DNS while it
//! runs) are copied by a sniffing handle, which never delays them; the first
//! connection to such an address can still go through the VPN, which works,
//! and later ones go direct.

use crate::netutil::is_globally_routable_ipv4;
use crate::split_capture::Handle;
use gamepath_engine::direct_list::{DirectList, DirectSpec, MAX_LEARNED};
use gamepath_engine::netconfig::{
    DIRECT_ROUTE_METRIC, add_route_via, remove_route_via, remove_routes_with_metric,
};
use gamepath_engine::{log_info, log_warn};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Instant;

/// What the data path and the DNS observer share.
pub(crate) struct DirectRouter {
    list: RwLock<Arc<DirectList>>,
    gateway: Ipv4Addr,
    interface: u32,
    /// Addresses that must stay inside the tunnel: its resolvers.
    protected: Vec<Ipv4Addr>,
    installed: Mutex<HashSet<(Ipv4Addr, u8)>>,
    /// Each learned address with the name it was learned for, so a list edit
    /// can drop exactly the ones it no longer covers.
    learned: Mutex<HashMap<Ipv4Addr, String>>,
    /// Bumped by every replacement and by teardown, so an install still
    /// running for an older list stops instead of racing the new one.
    generation: AtomicU64,
    stopped: AtomicBool,
}

impl DirectRouter {
    /// Learns from `packet` if it is a DNS reply for a direct name. Called on
    /// the downlink for every packet, so anything that is not a DNS reply
    /// returns before taking a lock.
    pub(crate) fn learn(&self, packet: &[u8]) {
        if !gamepath_engine::direct_list::is_dns_reply(packet) {
            return;
        }
        let list = Arc::clone(&self.list.read().unwrap());
        if !list.has_domains() {
            return;
        }
        for address in list.answered_addresses(packet) {
            if !is_globally_routable_ipv4(address)
                || list.contains(address)
                || self.protected.contains(&address)
            {
                continue;
            }
            // Held across the route call so teardown, which takes it too,
            // can never miss a route being added.
            let mut learned = self.learned.lock().unwrap();
            if self.stopped.load(Ordering::Acquire)
                || learned.contains_key(&address)
                || learned.len() >= MAX_LEARNED
            {
                continue;
            }
            match add_route_via(
                address,
                32,
                self.gateway,
                self.interface,
                DIRECT_ROUTE_METRIC,
            ) {
                Ok(()) => {
                    learned.insert(
                        address,
                        gamepath_engine::direct_list::reply_question(packet).unwrap_or_default(),
                    );
                }
                Err(error) => log_warn!("could not route a direct site around the VPN: {error}"),
            }
        }
    }

    fn install(&self, generation: u64) {
        let list = Arc::clone(&self.list.read().unwrap());
        let wanted: HashSet<(Ipv4Addr, u8)> = list.prefixes().into_iter().collect();
        let started = Instant::now();
        let stale: Vec<_> = self
            .installed
            .lock()
            .unwrap()
            .difference(&wanted)
            .copied()
            .collect();
        for prefix in &stale {
            remove_route_via(prefix.0, prefix.1, self.gateway, self.interface);
            self.installed.lock().unwrap().remove(prefix);
        }
        let mut added = 0;
        let mut failed = 0;
        for prefix in &wanted {
            if self.generation.load(Ordering::Acquire) != generation {
                return;
            }
            if self.installed.lock().unwrap().contains(prefix) {
                continue;
            }
            let mut installed = self.installed.lock().unwrap();
            match add_route_via(
                prefix.0,
                prefix.1,
                self.gateway,
                self.interface,
                DIRECT_ROUTE_METRIC,
            ) {
                Ok(()) => {
                    installed.insert(*prefix);
                    added += 1;
                }
                Err(error) => {
                    if failed == 0 {
                        log_warn!("could not route a direct range around the VPN: {error}");
                    }
                    failed += 1;
                }
            }
        }
        log_info!(
            "direct ranges routed around the VPN: {} in place, {added} added, {} removed, \
             {failed} failed, in {} ms",
            wanted.len(),
            stale.len(),
            started.elapsed().as_millis()
        );
    }

    fn remove_all(&self) {
        let started = Instant::now();
        let mut learned = self.learned.lock().unwrap();
        for address in learned.keys() {
            remove_route_via(*address, 32, self.gateway, self.interface);
        }
        let learned_count = learned.len();
        learned.clear();
        drop(learned);
        let mut installed = self.installed.lock().unwrap();
        for (destination, prefix) in installed.iter() {
            remove_route_via(*destination, *prefix, self.gateway, self.interface);
        }
        let installed_count = installed.len();
        installed.clear();
        if installed_count + learned_count > 0 {
            log_info!(
                "direct routes removed: {installed_count} range(s) and {learned_count} learned \
                 address(es) in {} ms",
                started.elapsed().as_millis()
            );
        }
    }
}

pub(crate) struct DirectRoutes {
    router: Arc<DirectRouter>,
    installer: Option<JoinHandle<()>>,
    observer: Option<(Arc<Handle>, JoinHandle<()>)>,
}

impl DirectRoutes {
    /// Starts routing `spec` around the tunnel. The ranges go in on a
    /// background thread: a country is a couple of thousand routes, and the
    /// VPN is usable, just not yet direct for them, while they do.
    pub(crate) fn start(
        spec: &DirectSpec,
        gateway: Ipv4Addr,
        interface: u32,
        protected: Vec<Ipv4Addr>,
    ) -> Self {
        let swept = remove_routes_with_metric(DIRECT_ROUTE_METRIC);
        if swept > 0 {
            log_info!("removed {swept} direct route(s) a previous session left behind");
        }
        let router = Arc::new(DirectRouter {
            list: RwLock::new(Arc::new(compile(spec, &protected))),
            gateway,
            interface,
            protected,
            installed: Mutex::new(HashSet::new()),
            learned: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(0),
            stopped: AtomicBool::new(false),
        });
        let mut routes = Self {
            router,
            installer: None,
            observer: None,
        };
        routes.refresh();
        routes
    }

    /// The shared half, for the downlink to learn from.
    pub(crate) fn router(&self) -> Arc<DirectRouter> {
        Arc::clone(&self.router)
    }

    /// Applies a new list without touching the tunnel. Unchanged ranges stay
    /// installed, so nothing that keeps its route ever loses it.
    pub(crate) fn replace(&mut self, spec: &DirectSpec) {
        let list = compile(spec, &self.router.protected);
        {
            let mut learned = self.router.learned.lock().unwrap();
            learned.retain(|address, name| {
                let keep = list.matches_name(name) && !list.contains(*address);
                if !keep {
                    remove_route_via(*address, 32, self.router.gateway, self.router.interface);
                }
                keep
            });
        }
        *self.router.list.write().unwrap() = Arc::new(list);
        self.refresh();
    }

    pub(crate) fn status(&self) -> Value {
        let list = Arc::clone(&self.router.list.read().unwrap());
        json!({
            "ranges": list.range_count(),
            "domains": list.domain_count(),
            "routes": self.router.installed.lock().unwrap().len(),
            "learned": self.router.learned.lock().unwrap().len(),
        })
    }

    fn refresh(&mut self) {
        let generation = self.router.generation.fetch_add(1, Ordering::AcqRel) + 1;
        if let Some(previous) = self.installer.take() {
            let _ = previous.join();
        }
        let router = Arc::clone(&self.router);
        self.installer = thread::Builder::new()
            .name("gamepath-direct-routes".into())
            .spawn(move || router.install(generation))
            .map_err(|error| log_warn!("could not start installing direct routes: {error}"))
            .ok();
        let wants_names = self.router.list.read().unwrap().has_domains();
        if wants_names && self.observer.is_none() {
            self.observer = start_observer(Arc::clone(&self.router))
                .map_err(|error| {
                    log_warn!("direct names learn only from the VPN's own lookups: {error}")
                })
                .ok();
        }
    }
}

impl Drop for DirectRoutes {
    fn drop(&mut self) {
        self.router.stopped.store(true, Ordering::Release);
        self.router.generation.fetch_add(1, Ordering::AcqRel);
        if let Some((handle, worker)) = self.observer.take() {
            handle.shutdown_receive();
            let _ = worker.join();
        }
        if let Some(installer) = self.installer.take() {
            let _ = installer.join();
        }
        self.router.remove_all();
    }
}

fn compile(spec: &DirectSpec, protected: &[Ipv4Addr]) -> DirectList {
    let mut list = DirectList::compile(spec);
    for address in protected {
        list.exclude(*address);
    }
    if list.skipped() > 0 {
        log_info!(
            "direct list: {} entr(ies) skipped as malformed, IPv6, or wider than /{}",
            list.skipped(),
            gamepath_engine::direct_list::MIN_PREFIX
        );
    }
    list
}

/// Copies every DNS reply the machine receives, whichever tunnel or resolver
/// it came from. Sniffing only: a reply is never held, so the game's lookups
/// pay nothing for it.
fn start_observer(router: Arc<DirectRouter>) -> Result<(Arc<Handle>, JoinHandle<()>), String> {
    const SNIFF_RECEIVE_ONLY: u64 = 0x0001 | 0x0004;
    let handle = Arc::new(Handle::open(
        &crate::split_capture::dll_path()?,
        "inbound and ip and udp.SrcPort == 53",
        0,
        gamepath_engine::role::Role::current().capture_priority(),
        SNIFF_RECEIVE_ONLY,
    )?);
    let receiver = Arc::clone(&handle);
    let worker = thread::Builder::new()
        .name("gamepath-direct-dns".into())
        .spawn(move || {
            let mut packet = vec![0_u8; 65_535];
            while let Ok((length, _)) = receiver.recv_into(&mut packet) {
                router.learn(&packet[..length]);
            }
        })
        .map_err(|error| format!("could not start the direct name observer: {error}"))?;
    Ok((handle, worker))
}
