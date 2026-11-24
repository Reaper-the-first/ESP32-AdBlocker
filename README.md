# ESP32 Ad Blocker and Wi-Fi Extender

An ESP32-S3-based DNS filtering project that creates a Wi-Fi access point for client devices, forwards internet traffic through an upstream Wi-Fi hotspot using NAT, and filters DNS requests against locally stored blocklists.

> **Project status:** Personal learning project. Tested on an ESP32-S3-N16R8 development board using PlatformIO and the Arduino framework. Your results may vary with board revisions, Arduino-ESP32 core versions, and network conditions.

## Features

- DNS forwarding through configurable upstream resolvers (Cloudflare primary and Google Public DNS backup in this version).
- DNS-based domain blocking, including a small built-in list and a downloaded StevenBlack hosts list.
- Large blocklist storage using LittleFS and a compact hash table in memory.
- DNS response caching to reduce repeated upstream lookups.
- Whitelist and manually managed blocklist support.
- Web dashboard for status, DNS activity, and domain management.
- Scheduled blocklist updates.
- Wi-Fi access point plus upstream station connection and NAT internet sharing.

DNS filtering is not a universal ad remover. It cannot reliably remove ads served from the same domains as desired content (for example, many in-stream video ads). Devices using encrypted DNS such as DNS-over-HTTPS or DNS-over-TLS may bypass this DNS filter.

## Hardware

- ESP32-S3 development board with sufficient flash and PSRAM (developed with an ESP32-S3-N16R8 configuration).
- A Wi-Fi network with internet access. During development, a phone hotspot was used as the upstream connection.
- USB data cable for programming and serial monitoring.

No external wiring is required for the basic configuration described here.

## Software

- Visual Studio Code
- PlatformIO IDE extension
- PlatformIO Espressif32 platform with the Arduino framework
- Git (optional, for version control)

## Configure credentials

1. Clone or download this repository.
2. In the project folder, copy `include/secrets.h.example` to `include/secrets.h`.
3. Edit `include/secrets.h` and set your upstream Wi-Fi name/password and the password for the ESP32 access point.
4. Keep `include/secrets.h` private. It is excluded by `.gitignore` and must never be committed.

Example on Linux:

```bash
cp include/secrets.h.example include/secrets.h
```

Use a strong access-point password of at least 8 characters. Do not reuse your personal hotspot password.

## Build and upload

1. Open this repository folder in VS Code.
2. Connect the ESP32-S3 board by USB.
3. Open the PlatformIO project tasks.
4. Run **Build**.
5. If the build succeeds, run **Upload**.
6. Open the PlatformIO Serial Monitor at **115200 baud**.

The supplied `platformio.ini` targets `esp32-s3-devkitc-1` with 16 MB flash and OPI PSRAM settings. These settings are specific to the development board used for this project and may need adjustment for other ESP32 boards.

## Using the device

1. Power on the ESP32-S3.
2. It connects to the upstream Wi-Fi network configured in `include/secrets.h`.
3. Connect a phone or computer to the ESP32 access point configured in the same file.
4. Open the dashboard at `http://192.168.4.1/` while connected to the ESP32 network.
5. Use the dashboard to inspect DNS activity and manage block/allow entries.

The default access-point address in the firmware is `192.168.4.1`. Keep the dashboard on a trusted network; this project does not implement dashboard authentication.

## Blocklist

The firmware downloads the StevenBlack unified hosts list:

<https://github.com/StevenBlack/hosts>

Please review the upstream project's terms and attribution requirements before redistributing its list or substantial portions of it. This repository contains the firmware, not a bundled copy of the downloaded list.

## Security and privacy notes

- Never publish Wi-Fi passwords, API keys, private certificates, or other credentials.
- `include/secrets.h` is intentionally ignored by Git.
- Change any credentials that have previously been exposed in source code, screenshots, logs, or chat uploads.
- The dashboard currently has no login protection. Use it only on a trusted network.
- DNS queries are sent to the configured upstream resolver when they are not blocked or cached. Consider the resolver's privacy policy when choosing a provider.

## Acknowledgements

This project was developed as a personal learning project to explore embedded systems, computer networking, DNS filtering, and ESP32 development.

I received substantial guidance and assistance from **ChatGPT by OpenAI** throughout development, including help with understanding concepts, debugging, implementation ideas, and code improvements. The project was built iteratively through hands-on testing, troubleshooting, and learning.

## License

The firmware and documentation in this repository are released under the MIT License. Third-party libraries and the externally downloaded blocklist remain subject to their respective licenses and terms.
