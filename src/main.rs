use std::{collections::{HashMap, HashSet}, net::IpAddr, process::Command, time::{Duration, Instant}};


use etherparse::{IpHeader, PacketHeaders};
use sysinfo::{PidExt, ProcessExt, ProcessRefreshKind, RefreshKind, System, SystemExt};
use winroute::{Route, RouteManager};

fn get_sot_pid(s: &System) -> Option<u32> { // get the pid of the Sea of Thieves process
    for process in s.processes_by_name("SoTGame.exe") {
        return Some(process.pid().as_u32());
    }

    None
}

fn get_sot_ports(pid: u32) -> Vec<u16> {
    let p = &pid.to_string();

    let cmd = Command::new("netstat")
        .arg("-anop")
        .arg("udp")
        .output()
        .unwrap();

    // jarringly, netstat output contains non-utf8 characters :)
    let filtered_stdout = cmd
        .stdout
        .iter()
        .filter(|c| c.is_ascii())
        .copied()
        .collect();

    String::from_utf8(filtered_stdout)
        .unwrap()
        .lines()
        .filter(|line| line.contains(p))
        .map(|f| {
            let addr = f.split_whitespace().skip(1).next().unwrap();
            let port = addr.split(':').last().unwrap();
            port.parse::<u16>().unwrap()
        })
        .collect()
}

fn main() {
    println!("🤔 Npcap installé ? ");
    unsafe {
        let try_load_wpcap = libloading::Library::new("wpcap.dll");
        if try_load_wpcap.is_err() {
            println!("{}", "*".repeat(80));
            println!("🛑 Erreur: Npcap n'est pas installé. :(");
            println!("Installe npcap depuis : \n  https://npcap.com/dist/npcap-1.81.exe");
            println!("***❗ ATTENTION : COCHER 'WinPcap API Compatibility' ***");
            println!("{}\n", "*".repeat(80));
            println!("Continuer ? (Y/N)");
            
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            let input = input.trim().to_lowercase();
            if !(input == "y" || input == "yes" || input == "o" || input == "oui") {
                std::process::exit(1);
            }
        }
    }

    // wait until we get a sot pid
    println!("En attente de lancement de Sea of Thieves... (Lance-le !)");
    let mut s =
        System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new()));

    let sot_pid = loop {
        if let Some(pid) = get_sot_pid(&s) {
            break pid;
        }
        s.refresh_processes();
    };

    println!("Trouvé ! PID: {}", sot_pid);

    let devices = pcap::Device::list().unwrap();
    let auto_found_dev = devices.iter().find(|d| {
        d.addresses.iter().any(|addr| {
            if let IpAddr::V4(addr) = addr.addr {
                addr.octets()[0] == 192 && addr.octets()[1] == 168
            } else {
                false
            }
        })
    });

    let dev = match auto_found_dev {
        Some(d) => d.clone(),
        None => {
            println!("Sélectionne ton périph réseau, le réglage auto n'a pas fonctionné.");
            println!("Adaptateurs Réseau reconnus sur ce PC : ");

            let devices = pcap::Device::list().expect("fail de la liste des périphériques");
            let mut i = 1;

            for device in devices.clone() {
                println!(
                    "    {i}. {:?}",
                    device.desc.clone().unwrap_or(device.name.clone())
                );
                i += 1;
            }

            // prompt user for their device
            println!(
                "Sélectionne ta carte WiFi ou Ethernet, ou si tu es sur un VPN, sélectionne le VPN: "
            );
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            let n = input.trim().parse::<usize>().unwrap() - 1;

            (&devices[n]).clone()
        }
    };

    let mut cap = pcap::Capture::from_device(dev)
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    let route_manager = RouteManager::new().unwrap();
    let the_void = "0.0.0.0".parse().unwrap();

    println!("Quel serveur veux-tu atteindre (Demande à tes potes !) (e.g. 20.213.146.107:30618)\n    Entre : \n- IP:PORT \nou\n- 'recherche' pour connaître le serveur actuel.");
    let mut target = String::new(); // ""
    std::io::stdin().read_line(&mut target).unwrap();
    let target = target.trim();
    
    if target.chars().any(|c| c.is_numeric()) {
        if let Some((ip, port)) = target.split_once(':') {
            println!("🔗 Parfait, serveur cible IP: {}, PORT: {}", ip, port);
        } else {
            println!("⚠️ Format invalide! Utilise IP:PORT (ex: 20.213.146.107:30618)");
            std::process::exit(1);
        }
    } else if target == "recherche" || target == "" {
        println!("🤔 Détection du serveur");
    } else {
        println!("⚠️ Format invalide! L'entrée doit contenir des chiffres");
        println!("\nAppuyez sur une touche pour quitter...");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        std::process::exit(1);
    }

    println!("En attente de connexion à un serveur Sea of Thieves...");
    let mut active_connections: HashMap<String, (Instant, u32)> = HashMap::new();
    let mut ip_history: HashMap<String, u32> = HashMap::new();
    let mut seen_ips: HashSet<String> = HashSet::new();
    let check_duration = Duration::from_secs(5); // Période d'observation
    let min_packets = 10; // Nombre minimum de paquets pour considérer une connexion comme active

    loop {
        if let Ok(raw_packet) = cap.next_packet() {
            if let Ok(packet) = PacketHeaders::from_ethernet_slice(raw_packet.data) {
                if let Some(IpHeader::Version4(ipv4, _)) = packet.ip {
                    if let Some(transport) = packet.transport {
                        if let Some(udp) = transport.udp() {
                            if udp.destination_port == 3075 || udp.destination_port == 30005 {
                                continue;
                            }

                            if get_sot_ports(sot_pid).contains(&udp.source_port) {
                                let ip = ipv4.destination.map(|c| c.to_string()).join(".");
                                let addr = format!("{}:{}", ip, udp.destination_port);

                                // Mise à jour du compteur de paquets pour cette IP
                                let now = Instant::now();
                                active_connections
                                    .entry(addr.clone())
                                    .and_modify(|(last_seen, count)| {
                                        *last_seen = now;
                                        *count += 1;
                                    })
                                    .or_insert((now, 1));

                                // Nettoyage des anciennes connexions
                                active_connections.retain(|_, (last_seen, _)| 
                                    now.duration_since(*last_seen) < check_duration
                                );

                                // Affichage des connexions actives
                                // Montrer la connexion active et le nombre de fois où elle a été vue
                                println!("\nConnexions actives détectées:");
                                for (addr, (_, count)) in active_connections.iter() {
                                    // Mettre à jour l'historique
                                    ip_history
                                        .entry(addr.to_string())
                                        .and_modify(|c| *c += 1)
                                        .or_insert(1);
                                    
                                    let status = if seen_ips.contains(addr) {
                                        "⚠️ Déjà vue"
                                    } else {
                                        seen_ips.insert(addr.to_string());
                                        "🆕 Nouvelle"
                                    };
                                    
                                    println!(
                                        "- {} ({} paquets) | {} | Vue {} fois au total", 
                                        addr, 
                                        count,
                                        status,
                                        ip_history.get(addr).unwrap()
                                    );
                                }

                                // Vérification de la connexion principale
                                let main_connection = active_connections
                                    .iter()
                                    .filter(|(_, (_, count))| *count >= min_packets)
                                    .max_by_key(|(_, (_, count))| *count);

                                if let Some((main_addr, _)) = main_connection {
                                    if target == "recherche" || target == "" {
                                        println!("\nConnexion principale: {}", main_addr);
                                        println!("Appuyez sur Entrée pour actualiser.");
                                        std::io::stdin().read_line(&mut String::new()).unwrap();
                                        continue;
                                    }

                                    if main_addr != &target {
                                        println!("FAIL {} ≠ {} pas le bon serveur. ", main_addr, target);
                                        
                                        let blocking_route =
                                        Route::new(ip.parse().unwrap(), 32).gateway(the_void);
                                        println!("🔒 IP bloquée");
                                        
                                        // add route
                                        if let Err(e) = route_manager.add_route(&blocking_route) {
                                            println!(
                                                "Error adding route for: {}:{} - {}",
                                                ip, udp.destination_port, e
                                            );
                                        } else {
                                            // wait for enter
                                            println!("Cliquer sur non sur 'Rejoindre la session précédente ?', et appuyer sur Entrée.");
                                            std::io::stdin().read_line(&mut String::new()).unwrap();
                                            
                                        }
                                        println!("🔓 Déblocage {}...", ip);

                                        // delete route, route_manager.delete_route doesn't work for some reason
                                        let status = Command::new("route")
                                            .arg("delete")
                                            .arg(ip)
                                            .status()
                                            .unwrap();
                                        if !status.success() {
                                            println!("Failed to delete route.");
                                        }

                                        println!("Relance une partie !");
                                    } else {
                                        println!("🎉🎉🎉 Trouvé ! {} 🎉🎉🎉", main_addr);
                                        std::io::stdin().read_line(&mut String::new()).unwrap();
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

