/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021-2022, Silicon Labs
 * Main authors:
 *     - Jérôme Pouiller <jerome.pouiller@silabs.com>
 */
mod wsbrddbusapi;

use std::time::Duration;
use dbus::blocking::Connection;
use dbus::arg::PropMap;
use dbus::arg::prop_cast;
use wsbrddbusapi::ComSilabsWisunBorderRouter;

fn format_byte_array(input: &Vec<u8>) -> String {
    input.iter().map(|n| format!("{:02x}", n)).collect::<Vec<String>>().join(":")
}

fn is_parent(node: &(Vec<u8>, PropMap), target: &Vec<u8>) -> bool {
    let parent: Option<&Vec<u8>> = prop_cast(&node.1, "parent");
    match parent {
        Some(x) if x == target => true,
        Some(_) => false,
        None => false,
    }
}

fn print_rpl_tree(links: &Vec<(Vec<u8>, PropMap)>, cur: &Vec<u8>, indent: &str) -> () {
    // FIXME: detect (and defeat) loops
    let mut children: Vec<&Vec<u8>> = links.iter().filter(|n| is_parent(n, cur)).map(|n| &n.0).collect();
    children.sort();
    if let Some((last_child, first_childs)) = children.split_last() {
        for c in first_childs {
            println!("{}|- {}", indent, format_byte_array(c));
            print_rpl_tree(links, c, &(indent.to_owned() + "|    "));
        }
        println!("{}`- {}", indent, format_byte_array(last_child));
        print_rpl_tree(links, last_child, &(indent.to_owned() + "     "));
    }
}

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
        println!("GAK[{}]: {}", i, format_byte_array(g));
    }
    let gtks = p.gtks().unwrap();
    for (i, g) in gtks.iter().enumerate() {
        println!("GTK[{}]: {}", i, format_byte_array(g));
    }
    let mac_br = p.hw_address().unwrap_or(vec![0; 8]);
    println!("{}", format_byte_array(&mac_br));
    let links = p.nodes().unwrap();
    print_rpl_tree(&links, &mac_br, "  ");
    Ok(())
}
