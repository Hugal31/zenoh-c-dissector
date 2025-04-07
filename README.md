# Zenoh dissectors

This repository contains Wireshark dissectors for Zenoh.

## Features

* [x] Zenoh Scouting protocol.
* [x] Zenoh protocol.
* [x] KeyExpr resolution accross multiple links.
* [x] Message decompression.
* [ ] Less used messages types (Transport-level OAM, JOIN).
* [ ] All the known extensions.

## Installation

1. Build
2. Copy or link `libzenoh.so` in ` ~/.local/lib/wireshark/plugins/4.4/epan/`
3. Copy or link `zenoh_scout.lua` and `zenoh_utils.lua` in ` ~/.local/lib/wireshark/plugins/`
