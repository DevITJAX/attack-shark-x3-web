# Open-Source Attack Shark X3 Web Configurator

A browser-based hardware configurator and reverse-engineered USB/HID protocol suite for the **Attack Shark X3** wireless/wired gaming mouse (PixArt PAW3395 sensor, Compx/BK3633 dual-mode architecture).

Built with **TypeScript, React, Vite, Vitest, WebHID, and a lightweight Python Win32 HID Bridge (`server.py`)** to replace the proprietary `X3.exe` Windows desktop utility.

---

## Key Features

- **Dual Interface Modes**:
  - **Classic X3 App View**: Pixel-accurate replica of the official `X3.exe` desktop software (6 vertical DPI sliders, 5 red mouse callout badges, collapsible right-hand sensor panels, Profile manager, Macro manager, and live battery indicator).
  - **Modern Enthusiast Dashboard**: Clean tabbed interface for **Dashboard**, **Performance & Sensor**, **Button Mapping**, **Profiles**, **Device Info & Matrix**, and **Diagnostics** (with live hex packet inspection and JSON diagnostic export).
- **Modular Hardware Abstraction Layer (`src/transport/hardwareManager.ts`)**:
  - **Native Bridge Mode (`server.py`)**: Uses Win32 `HidD_SetFeature` on `mi_02&col04` (`UsagePage=0x000B`) and `ReadFile` on `mi_02&col03` (`UsagePage=0x000A`) for 100% verified hardware reads and writes on Windows.
  - **Browser WebHID Mode (`navigator.hid`)**: Direct browser connection with strict `VID=0x1D57, PID=0xFA60/0xFA61` filtering, async `col03` input report listener, and automatic detection of the Windows `HidP_GetValueCaps` (`featureReports: []`) limitation.
  - **Mock Simulator Mode**: Full in-memory simulated Attack Shark X3 for offline UI development and testing without physical hardware.
- **Hardware Left-Click Safety Lock**:
  - Both the UI and protocol encoder (`buildButtonMappingPacket`) enforce that at least one primary button retains **Left Click (`0x02, 0x00, 0x00`)** and all **18 three-byte firmware slots** are populated, preventing accidental loss of mouse clicks.

---

## Feature Support Matrix

| Feature / Capability | Status | HID Report / Mechanism | Onboard Persistence | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **6-Stage DPI Values (50–26,000 DPI)** | **Verified** | Feature Report `0x04` (56 B) | Yes (Onboard Flash) | Encoded as `(DPI / 50) - 1` (16-bit split at `pkt[8..15]` and `pkt[16..23]`) |
| **Active DPI Stage Selection (`1`–`6`)** | **Verified** | Feature Report `0x04` (`pkt[24]`) | Yes (Onboard Flash) | 1-based stage index (`0x01`..`0x06`) + physical DPI button notification via `0x03` (`0x1000`) |
| **DPI Stage LED Colors (6 Stages)** | **Verified** | Feature Report `0x04` (`pkt[25..48]`) | Yes (Onboard Flash) | Controls the scroll-wheel indicator LED color for each DPI stage |
| **Polling Rate (125 / 250 / 500 / 1000 Hz)** | **Verified** | Feature Report `0x06` (9 B) | Yes (Onboard Flash) | Uses `[code, ~code]` complement verification (`0x08/0xF7`, `0x03/0xFC`, `0x02/0xFD`, `0x01/0xFE`) |
| **Lift-Off Distance (1 mm / 2 mm)** | **Verified** | Feature Report `0x04` (`pkt[3]`) | Yes (Onboard Flash) | `0x00` = 1 mm, `0x01` = 2 mm |
| **Motion Sync (Off / On)** | **Verified** | Feature Report `0x04` (`pkt[4]`) | Yes (Onboard Flash) | PAW3395 sensor motion synchronization |
| **Angle Snap (Off / On)** | **Verified** | Feature Report `0x04` (`pkt[6]`) | Yes (Onboard Flash) | Sensor linear angle snapping |
| **Ripple Control (Off / On)** | **Verified** | Feature Report `0x04` (`pkt[7]`) | Yes (Onboard Flash) | High-DPI jitter smoothing |
| **Key Response Time / Debounce (2–20 ms)** | **Verified** | Feature Report `0x05` (15 B, `pkt[10]`) | Yes (Onboard Flash) | Encoded in 2 ms increments (`pkt[10] = ms / 2`, default `4` = `8 ms`) |
| **Sleep / Hibernate Timer (1–30 min)** | **Verified** | Feature Report `0x05` (15 B, `pkt[9]`) | Yes (Onboard Flash) | Wireless inactivity sleep timer |
| **5-Button Remapping (18-Slot Table)** | **Verified** | Feature Report `0x08` (59 B) | Yes (Onboard Flash) | Populates all 18 three-byte firmware slots (`0x41C4AC` lookup table) |
| **Live Battery % & Charging Status** | **Verified** | Feature `0x0C` -> Input `0x03` (`0x4010`) | Real-Time Hardware | Queries `col04` (`0x0C`) and reads 5-byte response on `col03` (`byte[4] * 10%`) |
| **Mouse Attributes (Speed / Scroll / DblClick)** | **Verified (Host OS)** | Win32 `SystemParametersInfoW` | Host OS Registry | Matches `X3.exe` behavior (configured via OS API, not USB) |
| **Multiple Named Profiles & JSON Export/Import** | **Verified (Browser)** | `localStorage` + Onboard Sync | Browser + Active Flash | Switching profiles writes the selected profile to onboard mouse flash |
| **RGB Backlight Strip Effects** | **Unsupported** | N/A | N/A | Attack Shark X3 (49g) has no RGB backlight strip (hidden per hardware capability) |
| **Bulk Read of Existing Flash Settings** | **Unsupported** | Write-Only Firmware | N/A | Mouse firmware only pushes telemetry (`0x03`); `X3.exe` caches settings in `pro.data` |
| **Mock Device Mode** | **Simulated** | In-Memory Transport | Session | Clearly labeled `[SIMULATED]` for offline testing |

---

## Browser Compatibility & Windows WebHID Note

| Platform / Browser | Direct WebHID (`navigator.hid`) | Native Helper Bridge (`server.py`) | Why? |
| :--- | :--- | :--- | :--- |
| **Windows 10/11 (Chrome / Edge)** | Connects & reads `col03`, but **blocks Feature Writes on `col04`** | **100% Supported (Recommended)** | `mi_02&col04` declares `UsagePage=0x000B, Usage=0x0000`. Windows `HidP_GetValueCaps` returns `0` feature value caps, causing Chromium's Windows HID backend to reject `sendFeatureReport`. `server.py` calls `HidD_SetFeature` directly like `hiddriver_1.dll`. |
| **Linux (Chrome / Edge via `hidraw`)** | Supported (with `udev` rule for `1d57:fa60` / `1d57:fa61`) | Supported | Linux `hidraw` passes raw feature reports without Windows `HidP_GetValueCaps` filtering. |
| **Firefox / Safari** | Unsupported (No WebHID API) | **100% Supported** | Works in any modern browser when using `server.py`. |

---

## Getting Started

### 1. Run with Live Hardware on Windows (Recommended)

Start the local Python hardware bridge & web server on port `3000`:

```powershell
python server.py
```

Then open **`http://127.0.0.1:3000`** in any browser.

### 2. Development & Automated Tests (TypeScript + React + Vite + Vitest)

```powershell
# Install dependencies
npm install

# Run the automated protocol & checksum unit test suite
npm test

# Build the production TypeScript + React bundle into dist/
npm run build

# Start Vite dev server (proxies /api/* to server.py on port 3000)
npm run dev
```

---

## Documentation

- See [docs/reverse-engineering.md](file:///c:/Users/XEON/Desktop/attacksharkx3-web/docs/reverse-engineering.md) for the complete disassembly notes from `X3.exe` and `hiddriver_1.dll`, byte-by-byte packet layouts, checksum equations, and the USBPcap/Wireshark capture guide.
