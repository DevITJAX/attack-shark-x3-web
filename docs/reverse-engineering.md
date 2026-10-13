# Attack Shark X3 — Hardware & Protocol Reverse Engineering Report

## 1. Executive Summary

This document records the verified hardware discovery, binary reverse engineering, USB/HID descriptor analysis, and wire-protocol specification for the **Attack Shark X3** wireless/wired gaming mouse (PAW3395 optical sensor).

All findings in this document are derived from direct inspection of:
1. **Live physical hardware** connected to the host (`VID_1D57&PID_FA60`).
2. **Official Windows vendor binaries** located at `C:\Program Files (x86)\Attack SharkX3Mouse\`:
   - `X3.exe` (32-bit MFC/C++ GUI application, ImageBase `0x00400000`)
   - `hiddriver_1.dll` (Wireless 2.4 GHz HID transport library)
   - `hiddriver_2.dll` (USB Wired HID transport library)
3. **Official persisted profile data** at `C:\Users\XEON\AppData\Roaming\Attack SharkX3Mouse\ms_1\pro.data`.

---

## 2. Hardware Identification & USB/HID Topology

### 2.1 Supported USB Identifiers

Disassembly of `X3.exe` (`0x413110` initialization routine) confirms two hardware Product IDs under Vendor ID `0x1D57` (Xenta / Compx):

| Connection Mode | Vendor ID (VID) | Product ID (PID) | Transport Library | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **2.4 GHz Wireless Receiver** | `0x1D57` | `0xFA60` | `hiddriver_1.dll` | Default wireless dongle mode (`Set_VIDPID(0x1D57, 0xFA60)`) |
| **USB Type-C Wired** | `0x1D57` | `0xFA61` | `hiddriver_2.dll` | Direct wired mode (`Set_VIDPID(0x1D57, 0xFA61)`), prioritized if both connected |

> **Important Exclusion**: Other HID devices on the bus (such as `VID=0x258A, PID=0x0124` SINO WEALTH Gaming Keyboard) expose vendor-defined collections (`0xFF00`) but are unrelated peripherals and must be excluded by strict VID/PID filtering.

### 2.2 Enumerated Windows HID Collections (`VID_1D57&PID_FA60`)

Querying the connected Attack Shark X3 receiver via `SetupDiGetClassDevs` and `HidP_GetCaps` reveals the following top-level HID collections:

| Device Path Suffix | Usage Page | Usage | Input Len | Output Len | Feature Len | Role in `X3.exe` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `mi_00` | `0x0001` (Generic Desktop) | `0x0002` (Mouse) | 8 B | 0 B | 0 B | Standard boot/OS mouse movement & clicks |
| `mi_01&col01` | `0x0001` (Generic Desktop) | `0x0006` (Keyboard) | 9 B | 1 B | 0 B | Emulated keyboard macros & shortcuts |
| `mi_02&col01` | `0x000C` (Consumer) | `0x0001` (Consumer Control) | 3 B | 0 B | 0 B | Media keys (Volume, Play/Pause) |
| `mi_02&col02` | `0x0001` (Generic Desktop) | `0x0080` (System Control) | 2 B | 0 B | 0 B | System power/sleep keys |
| **`mi_02&col03`** | **`0x000A` (Ordinal)** | **`0x0000`** | **5 B** | **0 B** | **0 B** | **Async Device-to-Host Event Channel** (`Open_DevMonitor`) |
| **`mi_02&col04`** | **`0x000B` (Telephony)** | **`0x0000`** | **0 B** | **0 B** | **262 B** | **Host-to-Device Configuration Channel** (`Open_FeatureDevice`) |
| `mi_02&col05` | `0xFF00` (Vendor) | `0x000E` | 15 B | 0 B | 0 B | Auxiliary vendor input interface |

---

## 3. Why Browser-Only WebHID Fails on Windows (Root Cause Analysis)

In `hiddriver_1.dll`:
- `Open_FeatureDevice` (`RVA 0x2320` -> `0x13D0`) locates the collection where `UsagePage == 0x000B` and `Usage == 0x0000` (`mi_02&col04`).
- `SetFeature` (`RVA 0x2340`) sends configuration packets by calling the Win32 API `HidD_SetFeature(hDevice, lpReportBuffer, ReportBufferLength)` directly.

However, inspecting `HidP_GetCaps` on `mi_02&col04` reveals a firmware HID descriptor quirk:
- `FeatureReportByteLength = 262`
- `NumberFeatureButtonCaps = 0`
- `NumberFeatureValueCaps = 0` (because `Usage` is declared as `0x0000` without a valid Value Capability range in the descriptor).

### Impact on Chromium WebHID (Windows)
When Chrome/Edge on Windows enumerates a HID collection (`HidServiceWin::CreateDeviceInfo`), it populates `HIDCollectionInfo.featureReports` by calling `HidP_GetButtonCaps(HidP_Feature, ...)` and `HidP_GetValueCaps(HidP_Feature, ...)`. Because both return `0` capability items:
1. `device.collections` shows `featureReports: []` for `UsagePage: 11 (0x000B)`.
2. Calling `device.sendFeatureReport(reportId, data)` in the browser immediately throws:
   `NotSupportedError: Failed to write the feature report.`

### Architectural Solution
To guarantee 100% real hardware control without misleading the user:
1. **Local Helper Bridge (`server.py`)**: A lightweight Python service using `ctypes.windll.hid.HidD_SetFeature` on `mi_02&col04` and `kernel32.ReadFile` on `mi_02&col03`. This executes the exact kernel ioctl (`IOCTL_HID_SET_FEATURE`) that `hiddriver_1.dll` performs.
2. **WebHID Transport Layer**: Included in the TypeScript HAL (`src/transport/webhidTransport.ts`) for reading `col03` input reports (`0x03`) or operating on OS platforms (e.g., Linux `hidraw`) where raw feature reports are not blocked by `HidP_GetValueCaps`, while explicitly warning users on Windows when `featureReports.length === 0`.
3. **Mock Transport Layer**: Full in-memory hardware simulation (`src/transport/mockTransport.ts`) for testing and UI exploration without physical hardware.

---

## 4. Wire Protocol Specification

All configuration commands are sent as **HID Feature Reports** via `HidD_SetFeature` on `mi_02&col04`.
The first byte of the buffer is the **HID Report ID** (`0x04`, `0x05`, `0x06`, `0x08`, `0x09`, `0x0A`, `0x0C`), and the buffer length passed to `HidD_SetFeature` matches the exact packet length (`pkt[1]`).

### 4.1 Checksum Algorithm (`Sum16` Big-Endian)

Used by Reports `0x04`, `0x05`, and `0x08`:
```text
checksum = sum(pkt[3 : N]) & 0xFFFF
pkt[N]     = (checksum >> 8) & 0xFF   # High byte (Big-Endian)
pkt[N + 1] = checksum & 0xFF          # Low byte  (Big-Endian)
```

---

### 4.2 Report `0x0C`: Status & Battery Query (10 Bytes)

Disassembled from `X3.exe` (`0x4132b0`):
```text
Offset:  00  01  02  03  04  05  06  07  08  09
Bytes:   0C  0A  01  FE  01  FE  00  00  00  00
```
- `pkt[0] = 0x0C` (Report ID)
- `pkt[1] = 0x0A` (Length = 10 bytes)
- Sending this feature report on `col04` immediately triggers a 5-byte **HID Input Report (`0x03`)** on `col03`.

---

### 4.3 Input Report `0x03`: Async Hardware Telemetry on `col03` (5 Bytes)

Disassembled from `hiddriver_1.dll` (`0x10001B30`) and `X3.exe` (`0x4132D0` message handler for `WM_USER + 0x52F`):

```text
Offset:  00        01        02        03         04
Bytes:   03     msg_lo    msg_hi    param_lo   param_hi
```
Where `msg_type = (msg_hi << 8) | msg_lo`:
- **`msg_type == 0x4010` (`03 10 40 <charging> <level>`) — Battery & Charging Report**:
  - `param_lo`: `0x00` = Charging, `0x01` = Discharging (On Battery)
  - `param_hi`: Battery level `1..10` (`percentage = param_hi * 10%`). Verified live on hardware: `03 10 40 01 09` -> **90% (Discharging)**.
- **`msg_type == 0x1000` (`03 00 10 <stage_1_to_6> 00`) — Physical DPI Button Pressed**:
  - `param_lo`: Active DPI stage index (`1..6`, 1-based).
- **`msg_type == 0x5010` (`03 10 50 <awake_flag> 00`) — Sleep / Wake Event**:
  - `param_lo`: `0x00` = Mouse entered sleep, `0x01` = Mouse woke up.

---

### 4.4 Report `0x06`: Polling Rate (9 Bytes)

Disassembled from `X3.exe` (`0x413EB0`):
```text
Offset:  00  01  02    03       04     05  06  07  08
Bytes:   06  09  01  <code>  <~code>   00  00  00  00
```
- `pkt[3]` (`code`) and `pkt[4]` (`(~code) & 0xFF` bitwise complement):
  - **125 Hz** (Profile index `0`): `0x08`, `0xF7` (`06 09 01 08 F7 00 00 00 00`)
  - **250 Hz** (Profile index `1`): `0x03`, `0xFC` (`06 09 01 03 FC 00 00 00 00`)
  - **500 Hz** (Profile index `2`): `0x02`, `0xFD` (`06 09 01 02 FD 00 00 00 00`)
  - **1000 Hz** (Profile index `3`): `0x01`, `0xFE` (`06 09 01 01 FE 00 00 00 00`)

---

### 4.5 Report `0x04`: DPI Stages, Active Stage & Sensor Settings (56 Bytes)

Disassembled from `X3.exe` (`0x414000..0x414316`):

| Byte Offset | Profile Offset | Field Name | Encoding / Values |
| :--- | :--- | :--- | :--- |
| `0..2` | — | Header | `0x04, 0x38, 0x01` (Report ID `0x04`, Length `56`) |
| `3` | `+0x8B4` | **Lift-Off Distance (LOD)** | `0x00` = 1 mm, `0x01` = 2 mm |
| `4` | `+0x940` | **Motion Sync** | `0x00` = Off, `0x01` = On |
| `5` | `+0x904..0x920` | **DPI Stage Enable Mask** | Bitmask of enabled stages (`0x3F` for 6 stages) |
| `6` | `+0x944` | **Angle Snap** | `0x00` = Off, `0x01` = On |
| `7` | `+0x948` | **Ripple Control** | `0x00` = Off, `0x01` = On |
| `8..15` | `+0x8C4..0x8E0` | **DPI Step Low Bytes (8 stages)** | `((DPI // 50) - 1) & 0xFF` |
| `16..23` | `+0x8C4..0x8E0` | **DPI Step High Bytes (8 stages)** | `(((DPI // 50) - 1) >> 8) & 0xFF` |
| `24` | `+0x934` | **Active DPI Stage (1-based)** | `activeStageIndex + 1` (`0x01`..`0x06`) |
| `25..48` | `+0x960..0x97F` | **Stage Indicator RGB Colors** | 8 × 3-byte `[R, G, B]` stage LED colors |
| `49` | `+0x954` | Constant Flag | `0x01` |
| `50..51` | — | **Checksum (`Sum16` BE)** | Big-Endian 16-bit sum of `pkt[3..49]` |
| `52..55` | — | Padding | `0x00, 0x00, 0x00, 0x00` |

**Verified Example (Default Profile, Stage 2 = 1600 DPI active)**:
`04 38 01 00 00 3F 00 00 0F 1F 2F 3F 63 07 00 00 00 00 00 00 00 02 00 00 02 FF 00 00 00 FF 00 00 00 FF FF FF 00 00 FF FF FF 00 FF FF 40 00 FF FF FF 01 0E 7D 00 00 00 00`

---

### 4.6 Report `0x05`: Key Response Time (Debounce) & Sleep Timer (15 Bytes)

Disassembled from `X3.exe` (`0x413DB0..0x413E91` and UI formatter at `0x40F5F0`):
- Note: Although the packet structure is shared with Compx RGB mouse firmware, the Attack Shark X3 hardware has **no RGB backlight strip** (only the DPI indicator LED). In `X3.exe`, Report `0x05` carries the **Key Response Time (Debounce)** in `pkt[10]` and the **Power Management Sleep Timer** in `pkt[9]`.

| Byte Offset | Profile Offset | Field Name | Encoding / Values |
| :--- | :--- | :--- | :--- |
| `0..2` | — | Header | `0x05, 0x0F, 0x01` (Report ID `0x05`, Length `15`) |
| `3` | `+0x94C` | Reserved Mode Byte | `0x00` |
| `4` | `+0x928` | Reserved Speed Byte | `0x03` (`9 - 6`) |
| `5` | `+0x92C` | Reserved Brightness Byte | `0xA8` (`(10 << 4) | 0x08`) |
| `6..8` | `+0x95C` | Reserved RGB | `0x00, 0x00, 0xFF` |
| `9` | `+0x930` | **Sleep Timer Index** | `0x01`..`0x1E` (Default `0x01`) |
| `10` | `+0x958` | **Key Response Time (Debounce)** | `debounce_ms // 2` (`0x04` = `8 MS`, range `2..20 MS`) |
| `11..12` | — | **Checksum (`Sum16` BE)** | Big-Endian 16-bit sum of `pkt[3..10]` |
| `13..14` | — | Padding | `0x00, 0x00` |

**Verified Example (Default `8 MS` Key Response Time)**:
`05 0F 01 00 03 A8 00 00 FF 01 04 01 AF 00 00`

---

### 4.7 Report `0x08`: 18-Slot Button Mapping Table (59 Bytes)

Disassembled from `X3.exe` (`0x414600..0x414802`, lookup table at `0x41C4AC`, and default slot table at `0x41C9E0`):

- **Critical Safety Finding**: The packet contains **18 three-byte slots** (`pkt[3..56]`), not 5 or 6. Sending a packet with only 5 or 6 slots populated or using 0-indexed button codes disables the primary mouse clicks!
- In the firmware lookup table (`0x41C4AC`), `action_id = 0` maps to `(0x01, 0x00, 0x00)` (Unassigned), while **Left Click (`action_id = 1`) maps to `(0x02, 0x00, 0x00)`**.

#### Hardware Action Code Table (`0x41C4AC`)

| Action ID (`pro.data`) | Action Name | 3-Byte Firmware Tuple `(b0, b1, b2)` |
| :--- | :--- | :--- |
| `0x01` (1) | **Left Click** | `02 00 00` |
| `0x02` (2) | **Right Click** | `03 00 00` |
| `0x03` (3) | **Middle Button** | `04 00 00` |
| `0x04` (4) | **Backward (Side Rear)** | `06 00 00` |
| `0x05` (5) | **Forward (Side Front)** | `05 00 00` |
| `0x06` (6) | **DPI Loop (Cycle)** | `0D 00 00` |
| `0x07` (7) | **DPI +** | `0E 00 00` |
| `0x08` (8) | **DPI -** | `0F 00 00` |
| `0x16` (22) | **Three Click / Fire Key** | `10 00 03` |
| `0x0B` (11) | **Scroll Down** | `09 00 00` |
| `0x0C` (12) | **Scroll Up** | `0A 00 00` |
| `0x34` (52) | **Disable (Button Off)** | `3C 00 00` |
| `0x00` (0) | **Unused Slot Default** | `01 00 00` |

#### 18 Hardware Slots Layout (`pkt[3 + slot*3 .. 5 + slot*3]`)

| Slot Index | Packet Bytes | Physical Control / Role | Default Tuple |
| :--- | :--- | :--- | :--- |
| **Slot 0** | `pkt[3..5]` | **UI Button 1 (Left Click)** | `02 00 00` |
| **Slot 1** | `pkt[6..8]` | **UI Button 2 (Right Click)** | `03 00 00` |
| **Slot 2** | `pkt[9..11]` | **UI Button 3 (Middle Button)** | `04 00 00` |
| **Slot 3** | `pkt[12..14]` | **Bottom DPI Button** | `0D 00 00` |
| **Slot 4** | `pkt[15..17]` | Internal Reserved (Disabled) | `3C 00 00` |
| **Slot 5** | `pkt[18..20]` | Internal Reserved (DPI -) | `0F 00 00` |
| **Slot 6** | `pkt[21..23]` | **UI Button 5 (Backward / Side Rear)** | `06 00 00` |
| **Slot 7** | `pkt[24..26]` | **UI Button 4 (Forward / Side Front)** | `05 00 00` |
| **Slot 8** | `pkt[27..29]` | Internal Reserved (Disabled) | `3C 00 00` |
| **Slots 9..15** | `pkt[30..50]` | Unused Slots (7 slots) | `01 00 00` (each) |
| **Slot 16** | `pkt[51..53]` | **Scroll Wheel Up** | `0A 00 00` |
| **Slot 17** | `pkt[54..56]` | **Scroll Wheel Down** | `09 00 00` |

- `pkt[57..58]` = Big-Endian `sum(pkt[3:57]) & 0xFFFF` (`0x00, 0xC2` for factory defaults).

**Verified Default 59-Byte Packet**:
`08 3B 01 02 00 00 03 00 00 04 00 00 0D 00 00 3C 00 00 0F 00 00 06 00 00 05 00 00 3C 00 00 01 00 00 01 00 00 01 00 00 01 00 00 01 00 00 01 00 00 01 00 00 0A 00 00 09 00 00 00 C2`

---

## 5. Reproducible USBPcap & Wireshark Capture Workflow

To independently observe and verify any command sent by the official `X3.exe` utility:

1. **Install USBPcap & Wireshark**:
   - Ensure USBPcap is installed and identify the Root Hub hosting `VID_1D57&PID_FA60` (2.4G receiver) or `VID_1D57&PID_FA61` (wired mouse).
2. **Apply Wireshark Display Filter**:
   ```wireshark
   usb.idVendor == 0x1d57 || (usb.transfer_type == 0x02 && usb.setup.bRequest == 0x09)
   ```
   - `bRequest == 0x09` filters for USB HID `SET_REPORT` control transfers (`wValue = 0x03xx` where `0x03` is Feature Report and `xx` is the Report ID `04`, `05`, `06`, `08`, `0C`).
3. **Single-Variable Differential Capture**:
   - Launch `X3.exe` and capture the initial `0x0C` status query and `0x03` input response on endpoint `0x83`.
   - Change **one setting at a time** (e.g., switch Polling Rate from `1000Hz` to `500Hz`, or toggle `Ripple Control` from `Off` to `On`).
   - Compare the `HID Data` payload in the `SET_REPORT` (`URB_CONTROL out`) frame before and after the change, verifying the payload bytes and the 16-bit Big-Endian checksum at the end of the packet.

---

## 6. Onboard Persistence vs. Host-Side State

- **Stored in Mouse Onboard Flash Memory (Survives Reconnect & Different PC)**:
  - 6 DPI Stage values, Active DPI Stage (`1..6`), and Stage Indicator RGB colors (`Report 0x04`)
  - Lift-Off Distance (`1 mm` / `2 mm`), Motion Sync, Angle Snap, Ripple Control (`Report 0x04`)
  - Polling Rate (`125 / 250 / 500 / 1000 Hz`) (`Report 0x06`)
  - Key Response Time / Debounce (`2..20 ms`) and Sleep Timer (`Report 0x05`)
  - All 18 Hardware Button Mappings (`Report 0x08`)
- **Stored on Host Only (`pro.data` / Browser `localStorage` / Windows OS API)**:
  - Multiple Named Profiles (`Profile1`, `Profile2`, etc.): `X3.exe` stores named profiles in `%APPDATA%\Attack SharkX3Mouse\ms_1\pro.data` and writes the selected profile's active parameters to the mouse when switched.
  - **Mouse Attribute** (`Moving Speed`, `Double Click Speed`, `Rolling Speed`): Applied to Windows via `SystemParametersInfoW(SPI_SETMOUSESPEED / SPI_SETWHEELSCROLLLINES)` and `SetDoubleClickTime()`, not sent over USB.
- **Write-Only Configuration Protocol Limitation**:
  - While battery percentage, charging status (`0x4010`), physical DPI stage button presses (`0x1000`), and sleep/wake events (`0x5010`) are pushed by the mouse via Input Report `0x03`, the mouse firmware does **not** expose a bulk "read full DPI/button table from flash" command (`X3.exe` reads initial UI state from `pro.data`).

---

## 7. Hardware Readback Investigation & Verification (Live Physical Mouse)

On 2026-10-13, live hardware tests were executed against an active Attack Shark X3 (2.4 GHz receiver, `VID_1D57&PID_FA60`, PAW3395) using Win32 `HidD_GetFeature` via `server.py`:

### 7.1 HidD_GetFeature Verification Matrix

| Report ID | Length | Target Collection | Win32 HidD_GetFeature Result | Error Code / Details | Readability Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`0x04`** | 56 B | `mi_02&col04` (Feature) | `ok = False` | `121` (`ERROR_SEM_TIMEOUT`) | **Not Readable** (Firmware does not acknowledge GET_FEATURE) |
| **`0x05`** | 15 B | `mi_02&col04` (Feature) | `ok = False` | `121` (`ERROR_SEM_TIMEOUT`) | **Not Readable** (Times out after ~5s) |
| **`0x06`** | 9 B | `mi_02&col04` (Feature) | `ok = False` | `121` (`ERROR_SEM_TIMEOUT`) | **Not Readable** (Times out after ~5s) |
| **`0x08`** | 59 B | `mi_02&col04` (Feature) | `ok = False` | `121` (`ERROR_SEM_TIMEOUT`) | **Not Readable** (Times out after ~5s) |
| **`0x0C`** | 10 B | `mi_02&col04` (Feature) | `ok = False` | `121` (`ERROR_SEM_TIMEOUT`) | **Not Readable** (Only SET_FEATURE triggers async report 0x03 on col03) |
| Any | — | `mi_00` .. `col03` | N/A | `FeatureReportByteLength = 0` | Collection does not define Feature Reports |

### 7.2 Binary Profile Analysis (`pro.data`)

Because the firmware channel is write-only, the vendor software `X3.exe` persists and restores state through `%APPDATA%\Attack SharkX3Mouse\ms_1\pro.data`. Direct binary analysis of the physical user file confirmed the exact layout:

- **Struct Signature**: Little-endian `uint32 = 0x000001A4` (420 bytes)
- **`+0x004`**: Polling rate code (`1=1000Hz, 2=500Hz, 3=250Hz, 8=125Hz`)
- **`+0x00C`**: Stage count (`6`)
- **`+0x02C..+0x040`**: 6 × LE `uint32` DPI step values (`(DPI // 50) - 1`)
- **`+0x08C`**: Key Response Time / Debounce in ms (`8`)
- **`+0x090`**: Sleep Timer Index (`6` minutes)
- **`+0x094`**: Moving Speed / Pointer Speed (`10`)
- **`+0x098`**: Lift-Off Distance (`1` = 1 mm, `2` = 2 mm)
- **`+0x09C`**: Active DPI Stage index (`1` = Stage 2, 0-based)
- **`+0x0A0`**: Rolling Speed / Scroll Lines (`3`)
- **`+0x0C4..+0x0E0`**: 8 × LE `uint32` Stage LED Colors stored as `0x00RRGGBB`

### 7.3 Multi-Tier Readback Implementation

1. **Primary Source (`pro.data`)**: `%APPDATA%\Attack SharkX3Mouse\ms_1\pro.data` is parsed by `server.py` and returned via `/api/read-profile`.
2. **Diagnostic Probe**: Reports 0x04, 0x05, 0x06, 0x08 are probed in the background (and cached) so `/api/read-profile` returns instantly while recording the firmware timeout behavior in the Diagnostics tab.
3. **Decoders**: Both Python (`server.py`) and TypeScript (`src/protocol/x3Protocol.ts`) implement exact decoders for all four reports with unit tests covering round-trips.

