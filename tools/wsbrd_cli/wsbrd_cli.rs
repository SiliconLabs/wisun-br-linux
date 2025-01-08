/*
 * SPDX-License-Identifier: LicenseRef-MSLA
 * Copyright (c) 2021-2023 Silicon Laboratories Inc. (www.silabs.com)
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of the Silicon Labs Master Software License
 * Agreement (MSLA) available at [1].  This software is distributed to you in
 * Object Code format and/or Source Code format and is governed by the sections
 * of the MSLA applicable to Object Code, Source Code and Modified Open Source
 * Code. By using this software, you agree to the terms of the MSLA.
 *
 * [1]: https://www.silabs.com/about-us/legal/master-software-license-agreement
 */
#[allow(dead_code)]
mod wsbrddbusapi;

#[macro_use]
extern crate clap;
extern crate dbus;

use std::convert::TryInto;
use std::net::Ipv6Addr;
use std::time::Duration;
use dbus::blocking::Connection;
use wsbrddbusapi::ComSilabsWisunBorderRouter;
use clap::App;
use clap::AppSettings;
use clap::Arg;
use clap::SubCommand;

// Wi-SUN TBU 1.1.13 - BorderRouterInformationElement.format
#[allow(dead_code)]
enum WsIeType {
    Wh      = 0,
    WpShort = 1,
    WpLong  = 2,
}

// Wi-SUN Assigned Value Registry 0v26 - 7.2. Wi-SUN Payload Information
// Element Sub-IDs
#[allow(dead_code)]
enum WsIeWpShort {
    Pan      = 0x04, // PAN
    NetName  = 0x05, // Network Name
    PanVer   = 0x06, // PAN Version
    GtkHash  = 0x07, // GTK Hash
    Pom      = 0x08, // PHY Operating Modes
    Lbats    = 0x09, // LFN Broadcast Additional Transmit Schedule
    Jm       = 0x0a, // Join Metrics
    LfnVer   = 0x40, // LFN Version
    LgtkHash = 0x41, // LFN GTK Hash

    /*
     * Silicon Labs allocated IE ID, in the PAN-wide range for short payload
     * IEs to ensure propagation. May clash with future official Wi-SUN ID
     * allocations.
     */
    SlPanDefect = 0x49,
}

// Wi-SUN Assigned Value Registry 0v26 - 10 Wi-SUN Frame Types
#[allow(dead_code)]
enum WsFrameType {
    Pa    =  0,
    Pas   =  1,
    Pc    =  2,
    Pcs   =  3,
    Data  =  4,
    Ack   =  5,
    Eapol =  6,
    Lpa   =  9,
    Lpas  = 10,
    Lpc   = 11,
    Lpcs  = 12,
    Ext   = 15,
}

fn format_byte_array(input: &[u8]) -> String {
    input.iter().map(|n| format!("{:02x}", n)).collect::<Vec<_>>().join(":")
}

fn is_parent(node: &(Vec<u8>, bool, Vec<Vec<u8>>), target: &[u8]) -> bool {
    if node.2.is_empty() {
        false
    } else {
        AsRef::<[u8]>::as_ref(&node.2[0]) == target
    }
}

fn ipv6_from_vec(vec: &Vec<u8>) -> Ipv6Addr {
    let array: [u8; 16] = vec[..].try_into().unwrap();
    Ipv6Addr::from(array)
}

fn print_rpl_tree(links: &[(Vec<u8>, bool, Vec<Vec<u8>>)], parents: &[Vec<u8>], cur: &[u8], indent: &str) -> () {
    let mut children: Vec<_> = links.iter().filter(|n| is_parent(n, cur)).map(|n| &n.0).collect();
    children.sort();
    let mut new_parents = parents.to_vec();
    new_parents.push(cur.to_vec());
    if let Some((last_child, first_childs)) = children.split_last() {
        for c in first_childs {
            if new_parents.contains(c) {
                println!("{}|- {} (loop!)", indent, ipv6_from_vec(c));
            } else {
                println!("{}|- {}", indent, ipv6_from_vec(c));
                print_rpl_tree(links, &new_parents, c, &(indent.to_owned() + "|    "));
            }
        }
        if new_parents.contains(last_child) {
            println!("{}`- {} (loop!)", indent, ipv6_from_vec(last_child));
        } else {
            println!("{}`- {}", indent, ipv6_from_vec(last_child));
            print_rpl_tree(links, &new_parents, last_child, &(indent.to_owned() + "     "));
        }
    }
}

fn do_status(dbus_proxy: &dyn ComSilabsWisunBorderRouter) -> Result<(), Box<dyn std::error::Error>> {
    // Consider that if NetworkName does not exist, the service probably not here.
    match dbus_proxy.wisun_network_name() {
        Ok(val) => println!("network_name: {}", val),
        Err(e) => return Err(Box::new(e)),
    }

    match dbus_proxy.wisun_fan_version().unwrap_or(std::u8::MAX) {
        1 => println!("fan_version: FAN 1.0"),
        2 => println!("fan_version: FAN 1.1"),
        _ => (),
    }
    println!("domain: {}", dbus_proxy.wisun_domain().unwrap_or("[UNKNOWN]".to_string()));
    let mode         = dbus_proxy.wisun_mode().unwrap_or(0);
    let class        = dbus_proxy.wisun_class().unwrap_or(0);
    let phy_mode_id  = dbus_proxy.wisun_phy_mode_id().unwrap_or(0);
    let chan_plan_id = dbus_proxy.wisun_chan_plan_id().unwrap_or(0);
    if mode != 0 && class != 0 {
        println!("mode: {:x}", mode);
        println!("class: {}", class);
    } else if phy_mode_id != 0 && chan_plan_id != 0 {
        println!("phy_mode_id: {}", phy_mode_id);
        println!("chan_plan_id: {}", chan_plan_id);
    }
    println!("panid: {:#04x}", dbus_proxy.wisun_pan_id().unwrap_or(0));
    println!("size: {}", dbus_proxy.wisun_size().unwrap_or("[UNKNOWN]".to_string()));

    let gaks = dbus_proxy.gaks().unwrap_or(vec![]);
    for (i, g) in gaks.iter().enumerate() {
        println!("GAK[{}]: {}", i, format_byte_array(g));
    }

    let gtks = dbus_proxy.gtks().unwrap_or(vec![]);
    for (i, g) in gtks.iter().enumerate() {
        println!("GTK[{}]: {}", i, format_byte_array(g));
    }

    let lgaks = dbus_proxy.lgaks().unwrap_or(vec![]);
    for (i, g) in lgaks.iter().enumerate() {
        println!("LGAK[{}]: {}", i, format_byte_array(g));
    }

    let lgtks = dbus_proxy.lgtks().unwrap_or(vec![]);
    for (i, g) in lgtks.iter().enumerate() {
        println!("LGTK[{}]: {}", i, format_byte_array(g));
    }

    let graph = dbus_proxy.routing_graph().unwrap();
    let br = graph.iter().find(|n| n.2.is_empty()).unwrap();
    println!("{}", ipv6_from_vec(&br.0));
    print_rpl_tree(&graph, &vec![], &br.0, "  ");
    Ok(())
}

fn do_pan_defect_start(dbus_proxy: &dyn ComSilabsWisunBorderRouter,
                       min_delay_s: u32, max_delay_s: u32) -> Result<(), Box<dyn std::error::Error>> {
    let mut data: Vec<u8> = vec![];
    data.push(true as u8); // Enable
    data.extend_from_slice(&min_delay_s.to_le_bytes());
    data.extend_from_slice(&max_delay_s.to_le_bytes());
    dbus_proxy.ie_custom_insert(
        WsIeType::WpShort as u8,
        WsIeWpShort::SlPanDefect as u8,
        data,
        vec![WsFrameType::Pc as u8]
    )?;
    Ok(())
}

fn do_pan_defect_stop(dbus_proxy: &dyn ComSilabsWisunBorderRouter) -> Result<(), Box<dyn std::error::Error>> {
    dbus_proxy.ie_custom_insert(
        WsIeType::WpShort as u8,
        WsIeWpShort::SlPanDefect as u8,
        vec![],
        vec![]
    )?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("wsbrd_cli")
        .setting(AppSettings::SubcommandRequired)
        .args_from_usage("--user 'Use user bus instead of system bus'")
        .subcommand(SubCommand::with_name("status")
            .about("Display a brief status of the Wi-SUN network")
        )
        .subcommand(SubCommand::with_name("pan-defect")
            .about("Toggle the Silicon Labs PAN Defect procedure to attempt a PAN transition \
                    (see https://docs.silabs.com/wisun/latest/wisun-pan-defect)")
            .setting(AppSettings::SubcommandRequired)
            .subcommand(SubCommand::with_name("start")
                .about("Start propagating the PAN Defect IE")
                .args(&[
                    Arg::with_name("min-delay")
                        .help("Minimum delay (seconds) between PAN defect IE reception and PAN switch"),
                    Arg::with_name("max-delay")
                        .help("Maximum delay (seconds) between PAN defect IE reception and PAN switch"),
                ])
            )
            .subcommand(SubCommand::with_name("stop")
                .about("Return to normal operation")
            )
        )
        .get_matches();

    let dbus_conn;
    if matches.is_present("user") {
        dbus_conn = Connection::new_session()?;
    } else {
        dbus_conn = Connection::new_system()?;
    }
    let dbus_proxy = dbus_conn.with_proxy("com.silabs.Wisun.BorderRouter",
                                          "/com/silabs/Wisun/BorderRouter",
                                          Duration::from_millis(500));

    match matches.subcommand() {
        ("status", _) => do_status(&dbus_proxy),
        ("pan-defect", Some(submatches)) => {
            match submatches.subcommand() {
                ("start", Some(subsubmatches)) => {
                    let min_delay_s = value_t!(subsubmatches, "min-delay", u32).unwrap_or_else(|e| e.exit());
                    let max_delay_s = value_t!(subsubmatches, "max-delay", u32).unwrap_or_else(|e| e.exit());
                    do_pan_defect_start(&dbus_proxy, min_delay_s, max_delay_s)
                }
                ("stop", _) => do_pan_defect_stop(&dbus_proxy),
                _ => Ok(()), // Already covered by AppSettings::SubcommandRequired
            }
        }
        _ => Ok(()), // Already covered by AppSettings::SubcommandRequired
    }
}
