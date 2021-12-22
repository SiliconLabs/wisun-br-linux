/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021-2022, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
mod wsbrddbusapi;

use std::time::Duration;
use dbus::blocking::Connection;
use wsbrddbusapi::ComSilabsWisunBorderRouter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let c = Connection::new_session()?;
    let p = c.with_proxy("com.silabs.Wisun.BorderRouter", "/com/silabs/Wisun/BorderRouter", Duration::from_millis(500));

    println!("network_name: {}", p.wisun_network_name().unwrap());
    println!("domain: {}", p.wisun_domain().unwrap());
    println!("mode: {:x}", p.wisun_mode().unwrap());
    println!("class: {}", p.wisun_class().unwrap());
    println!("panid: {:#04x}", p.wisun_pan_id().unwrap());
    println!("size: {}", p.wisun_size().unwrap());
    let gaks = p.gaks().unwrap();
    for (i, g) in gaks.iter().enumerate() {
        let tmp = g.iter().map(|n| format!("{:02x}", n)).collect::<Vec<String>>().join(":");
        println!("GAK[{}]: {}", i, tmp);
    }
    let gtks = p.gtks().unwrap();
    for (i, g) in gtks.iter().enumerate() {
        let tmp = g.iter().map(|n| format!("{:02x}", n)).collect::<Vec<String>>().join(":");
        println!("GTK[{}]: {}", i, tmp);
    }
    let daos = p.nodes().unwrap();
    for d in daos {
        let tmp1 = d.0.iter().map(|n| format!("{:02x}", n)).collect::<Vec<String>>().join(":");
        let tmp2 = d.1.iter().map(|n| format!("{:02x}", n)).collect::<Vec<String>>().join(":");
        println!("Node: {} -> {}", tmp1, tmp2);
    }
    Ok(())
}
