import ctypes
from ctypes import wintypes
import json
import os
import struct
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler

# Windows API definitions
hid = ctypes.windll.hid
setupapi = ctypes.windll.setupapi
kernel32 = ctypes.windll.kernel32

kernel32.CreateFileA.restype = ctypes.c_void_p
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
kernel32.ReadFile.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.c_void_p,
]
hid.HidD_GetPreparsedData.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
hid.HidD_FreePreparsedData.argtypes = [ctypes.c_void_p]
hid.HidP_GetCaps.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
hid.HidD_GetAttributes.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
hid.HidD_SetFeature.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.ULONG]
hid.HidD_GetFeature.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.ULONG]
setupapi.SetupDiGetClassDevsA.restype = ctypes.c_void_p

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_byte * 8),
    ]

class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("InterfaceClassGuid", GUID),
        ("Flags", wintypes.DWORD),
        ("Reserved", ctypes.c_void_p),
    ]

class HIDD_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Size", wintypes.ULONG),
        ("VendorID", wintypes.USHORT),
        ("ProductID", wintypes.USHORT),
        ("VersionNumber", wintypes.USHORT),
    ]

# Hardware action mapping table from X3.exe (0x41C4AC)
BUTTON_HW_MAP = {
    1: (0x02, 0x00, 0x00),   # Left Click
    2: (0x03, 0x00, 0x00),   # Right Click
    3: (0x04, 0x00, 0x00),   # Middle Click
    4: (0x06, 0x00, 0x00),   # Backward
    5: (0x05, 0x00, 0x00),   # Forward
    6: (0x0D, 0x00, 0x00),   # DPI Cycle (Loop)
    7: (0x0E, 0x00, 0x00),   # DPI +
    8: (0x0F, 0x00, 0x00),   # DPI -
    9: (0x10, 0x00, 0x03),   # Fire / Triple Click
    10: (0x18, 0x00, 0x00),  # Volume Up
    11: (0x19, 0x00, 0x00),  # Volume Down
    12: (0x17, 0x00, 0x00),  # Mute
    13: (0x15, 0x00, 0x00),  # Media Play/Pause
    14: (0x1B, 0x00, 0x00),  # Next Track
    15: (0x1A, 0x00, 0x00),  # Prev Track
    0: (0x3C, 0x00, 0x00),   # Disabled
}

POLLING_RATE_MAP = {
    125: 0x08,
    250: 0x03,
    500: 0x02,
    1000: 0x01,
}


class AttackSharkHardwareBridge:
    def __init__(self):
        self.lock = threading.Lock()
        self.feature_path = None
        self.input_path = None
        self.vid = None
        self.pid = None
        self.mode_name = "Disconnected"
        self.battery = 90
        self.charging = False
        self.sleeping = False
        self.active_dpi_stage = 0
        self.polling_rate = 1000
        self.last_events = []
        self.monitor_thread = None
        self.running = True

        self.discover_devices()
        self.start_input_monitor()
        self.query_battery()

    def discover_devices(self):
        hid_guid = GUID()
        hid.HidD_GetHidGuid(ctypes.byref(hid_guid))
        h_dev_info = setupapi.SetupDiGetClassDevsA(ctypes.byref(hid_guid), None, None, 0x12)
        if not h_dev_info or h_dev_info == 0xFFFFFFFFFFFFFFFF:
            return False

        dev_interface_data = SP_DEVICE_INTERFACE_DATA()
        dev_interface_data.cbSize = ctypes.sizeof(SP_DEVICE_INTERFACE_DATA)

        found_feat = None
        found_in = None
        found_vid = None
        found_pid = None

        index = 0
        while setupapi.SetupDiEnumDeviceInterfaces(
            ctypes.c_void_p(h_dev_info), None, ctypes.byref(hid_guid), index, ctypes.byref(dev_interface_data)
        ):
            required_size = wintypes.DWORD()
            setupapi.SetupDiGetDeviceInterfaceDetailA(
                ctypes.c_void_p(h_dev_info),
                ctypes.byref(dev_interface_data),
                None,
                0,
                ctypes.byref(required_size),
                None,
            )
            detail_buffer = ctypes.create_string_buffer(required_size.value)
            struct.pack_into("I", detail_buffer, 0, 8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 5)

            if setupapi.SetupDiGetDeviceInterfaceDetailA(
                ctypes.c_void_p(h_dev_info),
                ctypes.byref(dev_interface_data),
                detail_buffer,
                required_size.value,
                None,
                None,
            ):
                device_path = detail_buffer.raw[4:].split(b"\x00")[0]
                path_lower = device_path.lower()
                # Check Attack Shark X3 VID=1D57, PID=FA60 (2.4G Wireless) or FA61 (USB Wired)
                if b"vid_1d57" in path_lower and (b"pid_fa60" in path_lower or b"pid_fa61" in path_lower):
                    h_file = kernel32.CreateFileA(device_path, 0, 3, None, 3, 0, None)
                    if h_file and h_file != 0xFFFFFFFFFFFFFFFF:
                        attrs = HIDD_ATTRIBUTES()
                        attrs.Size = ctypes.sizeof(HIDD_ATTRIBUTES)
                        hid.HidD_GetAttributes(h_file, ctypes.byref(attrs))

                        preparsed = ctypes.c_void_p()
                        if hid.HidD_GetPreparsedData(h_file, ctypes.byref(preparsed)):
                            caps_raw = (wintypes.USHORT * 32)()
                            hid.HidP_GetCaps(preparsed, caps_raw)
                            hid.HidD_FreePreparsedData(preparsed)
                            usage = caps_raw[0]
                            usage_page = caps_raw[1]

                            # In hiddriver_1.dll:
                            # Open_FeatureDevice: UsagePage == 0x000B, Usage == 0x0000
                            # OpenHidDevice (Input Monitor): UsagePage == 0x000A, Usage == 0x0000
                            if usage_page == 0x000B and usage == 0x0000:
                                # Prefer Wired (0xFA61) if both plugged in, or whichever is active
                                if found_feat is None or attrs.ProductID == 0xFA61:
                                    found_feat = device_path
                                    found_vid = attrs.VendorID
                                    found_pid = attrs.ProductID
                            elif usage_page == 0x000A and usage == 0x0000:
                                if found_in is None or attrs.ProductID == 0xFA61:
                                    found_in = device_path

                        kernel32.CloseHandle(h_file)
            index += 1

        setupapi.SetupDiDestroyDeviceInfoList(ctypes.c_void_p(h_dev_info))

        with self.lock:
            self.feature_path = found_feat
            self.input_path = found_in
            self.vid = found_vid
            self.pid = found_pid
            if found_pid == 0xFA61:
                self.mode_name = "USB Wired (PID 0xFA61)"
            elif found_pid == 0xFA60:
                self.mode_name = "2.4GHz Wireless (PID 0xFA60)"
            else:
                self.mode_name = "Disconnected"

        return found_feat is not None

    def start_input_monitor(self):
        if self.monitor_thread and self.monitor_thread.is_alive():
            return

        def monitor_loop():
            while self.running:
                if not self.input_path:
                    time.sleep(2.0)
                    self.discover_devices()
                    continue

                h_in = kernel32.CreateFileA(self.input_path, 0xC0000000, 3, None, 3, 0, None)
                if not h_in or h_in == 0xFFFFFFFFFFFFFFFF:
                    time.sleep(2.0)
                    self.discover_devices()
                    continue

                buf = (ctypes.c_ubyte * 5)()
                read_bytes = wintypes.DWORD()
                while self.running:
                    ok = kernel32.ReadFile(h_in, buf, 5, ctypes.byref(read_bytes), None)
                    if not ok or read_bytes.value == 0:
                        break
                    raw = list(buf[: read_bytes.value])
                    # Parse 5-byte input report from col03 (matching X3.exe 0x4132d0)
                    if len(raw) >= 5 and raw[0] == 0x03:
                        msg_type = raw[1] | (raw[2] << 8)
                        param_lo = raw[3]
                        param_hi = raw[4]
                        if msg_type == 0x4010:
                            # Battery & charging report
                            if 1 <= param_hi <= 10:
                                self.battery = param_hi * 10
                            self.charging = param_lo == 0
                            self.sleeping = False
                        elif msg_type == 0x1000:
                            # Physical DPI button pressed on mouse (param_lo is 1..6)
                            if 1 <= param_lo <= 6:
                                self.active_dpi_stage = param_lo - 1
                        elif msg_type == 0x2000:
                            # Physical polling rate switch
                            pass
                        elif msg_type == 0x5010:
                            # Sleep / wake report
                            self.sleeping = param_lo == 0

                        self.last_events.append(
                            {
                                "time": time.strftime("%H:%M:%S"),
                                "bytes": [f"{b:02X}" for b in raw],
                                "type": f"0x{msg_type:04X}",
                            }
                        )
                        self.last_events = self.last_events[-20:]

                kernel32.CloseHandle(h_in)
                time.sleep(1.0)

        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()

    def send_feature_packet(self, packet_bytes):
        if not self.feature_path:
            self.discover_devices()
        if not self.feature_path:
            return {"ok": False, "error": "Attack Shark X3 feature interface not found"}

        with self.lock:
            h_feat = kernel32.CreateFileA(self.feature_path, 0xC0000000, 3, None, 3, 0, None)
            if not h_feat or h_feat == 0xFFFFFFFFFFFFFFFF:
                err = kernel32.GetLastError()
                return {"ok": False, "error": f"CreateFileA failed with error {err}"}

            length = len(packet_bytes)
            buf = (ctypes.c_ubyte * length).from_buffer_copy(bytes(packet_bytes))
            ok = hid.HidD_SetFeature(h_feat, buf, length)
            err = kernel32.GetLastError() if not ok else 0
            kernel32.CloseHandle(h_feat)

            return {
                "ok": bool(ok),
                "error_code": err,
                "length": length,
                "report_id": f"0x{packet_bytes[0]:02X}",
                "hex": " ".join(f"{b:02X}" for b in packet_bytes),
            }

    def query_battery(self):
        # 10-byte status query (0x0C, 0x0A, 0x01, 0xFE, 0x01, 0xFE, 0, 0, 0, 0)
        pkt = bytes([0x0C, 0x0A, 0x01, 0xFE, 0x01, 0xFE, 0x00, 0x00, 0x00, 0x00])
        res = self.send_feature_packet(pkt)
        time.sleep(0.08)
        return res

    @staticmethod
    def build_polling_packet(rate_hz):
        code = POLLING_RATE_MAP.get(int(rate_hz), 0x01)
        not_code = (~code) & 0xFF
        return bytes([0x06, 0x09, 0x01, code, not_code, 0x00, 0x00, 0x00, 0x00])

    @staticmethod
    def build_dpi_sensor_packet(active_stage, stages, stage_colors, lod, motion_sync, ripple, angle_snap):
        # 56-byte packet matching X3.exe 0x414000..0x414316
        # pkt[3]  = [edx+0x8b4] Lift of Distance (0 = 1MM, 1 = 2MM)
        # pkt[4]  = [edx+0x940] Motion Sync (0 = Off, 1 = On)
        # pkt[5]  = [edx+0x904..0x920] Stage enable bitmask (0x3F for 6 stages)
        # pkt[6]  = [edx+0x944] Angle Snap (0 = Off, 1 = On)
        # pkt[7]  = [edx+0x948] Ripple Control (0 = Off, 1 = On)
        # pkt[8..15]  = Low byte of (DPI/50 - 1) for 8 stages
        # pkt[16..23] = High byte of (DPI/50 - 1) for 8 stages
        # pkt[24] = [edx+0x934] + 1 (1-based Active DPI Stage: 1..6)
        # pkt[25..48] = 8 stage RGB colors (24 bytes)
        # pkt[49] = 0x01
        # pkt[50..51] = Big-Endian sum(pkt[3:50])
        pkt = bytearray(56)
        pkt[0] = 0x04
        pkt[1] = 0x38
        pkt[2] = 0x01
        pkt[3] = 1 if int(lod) == 2 else 0
        pkt[4] = 1 if motion_sync else 0

        count = min(len(stages), 6)
        pkt[5] = (1 << count) - 1  # 0x3F for 6 stages
        pkt[6] = 1 if angle_snap else 0
        pkt[7] = 1 if ripple else 0

        for i in range(6):
            dpi_val = int(stages[i]) if i < len(stages) else 800
            dpi_val = max(50, min(26000, dpi_val))
            step_val = max(0, (dpi_val // 50) - 1)
            pkt[8 + i] = step_val & 0xFF
            pkt[16 + i] = (step_val >> 8) & 0xFF

        # 1-based Active DPI Stage (1..6) at pkt[24]
        pkt[24] = (max(0, min(5, int(active_stage))) + 1) & 0xFF

        # 8 stage RGB colors at pkt[25..48]
        default_cols = [
            (255, 0, 0),
            (0, 255, 0),
            (0, 0, 255),
            (255, 255, 0),
            (0, 255, 255),
            (255, 0, 255),
            (255, 64, 0),
            (255, 255, 255),
        ]
        for i in range(8):
            r, g, b = default_cols[i]
            if stage_colors and i < len(stage_colors):
                c = str(stage_colors[i]).lstrip("#")
                if len(c) == 6:
                    r = int(c[0:2], 16)
                    g = int(c[2:4], 16)
                    b = int(c[4:6], 16)
            pkt[25 + i * 3 + 0] = r & 0xFF
            pkt[25 + i * 3 + 1] = g & 0xFF
            pkt[25 + i * 3 + 2] = b & 0xFF

        pkt[49] = 0x01
        chk = sum(pkt[3:50]) & 0xFFFF
        pkt[50] = (chk >> 8) & 0xFF
        pkt[51] = chk & 0xFF
        return bytes(pkt)

    @staticmethod
    def build_lighting_packet(debounce_ms=8, sleep_index=1, mode=0, brightness=100, speed=6, hex_color="#0000FF"):
        # 15-byte packet matching X3.exe 0x413db0..0x413e91
        # pkt[3]  = ([edi+0x94c] << 4) (default 0x00)
        # pkt[4]  = 9 - [edi+0x928] (default 9 - 6 = 0x03)
        # pkt[5]  = ([edi+0x92c] << 4) | 0x08 (default 0xA8)
        # pkt[6..8] = R, G, B (default 0x00, 0x00, 0xFF)
        # pkt[9]  = [edi+0x930] Sleep Time index (default 1)
        # pkt[10] = [edi+0x958] Key Response Time / 2 (default 4 for 8 MS)
        # pkt[11..12] = Big-Endian sum(pkt[3:11])
        pkt = bytearray(15)
        pkt[0] = 0x05
        pkt[1] = 0x0F
        pkt[2] = 0x01

        r, g, b = 0, 0, 255
        if hex_color:
            c = str(hex_color).lstrip("#")
            if len(c) == 6:
                r = int(c[0:2], 16)
                g = int(c[2:4], 16)
                b = int(c[4:6], 16)

        speed_val = max(1, min(9, int(speed)))
        bright_val = max(1, min(10, int(round(int(brightness) / 10))))
        debounce_step = max(1, min(15, int(round(int(debounce_ms) / 2))))

        pkt[3] = ((int(mode) & 0x0F) << 4) & 0xFF
        pkt[4] = (9 - speed_val) & 0x0F
        pkt[5] = ((bright_val & 0x0F) << 4) | 0x08
        pkt[6] = r & 0xFF
        pkt[7] = g & 0xFF
        pkt[8] = b & 0xFF
        pkt[9] = max(1, min(30, int(sleep_index))) & 0xFF
        pkt[10] = debounce_step & 0xFF

        chk = sum(pkt[3:11]) & 0xFFFF
        pkt[11] = (chk >> 8) & 0xFF
        pkt[12] = chk & 0xFF
        return bytes(pkt)

    @staticmethod
    def build_buttons_packet(button_actions):
        # 59-byte packet matching X3.exe 0x414600..0x414802 (18 three-byte slots at pkt[3..56])
        pkt = bytearray(59)
        pkt[0] = 0x08
        pkt[1] = 0x3B
        pkt[2] = 0x01

        # Default 18 hardware slots from X3.exe (0x41C9E0 mapped via 0x41C4AC)
        slots = [
            (0x02, 0x00, 0x00),  # Slot 0: Left Click
            (0x03, 0x00, 0x00),  # Slot 1: Right Click
            (0x04, 0x00, 0x00),  # Slot 2: Middle Click
            (0x0D, 0x00, 0x00),  # Slot 3: DPI Button (DPI Cycle)
            (0x3C, 0x00, 0x00),  # Slot 4: Disabled (0x34 -> 0x3C)
            (0x0F, 0x00, 0x00),  # Slot 5: DPI - (0x08 -> 0x0F)
            (0x06, 0x00, 0x00),  # Slot 6: Side Rear / Backward (0x04 -> 0x06)
            (0x05, 0x00, 0x00),  # Slot 7: Side Front / Forward (0x05 -> 0x05)
            (0x3C, 0x00, 0x00),  # Slot 8: Disabled (0x34 -> 0x3C)
            (0x01, 0x00, 0x00),  # Slot 9: Unused (0x00 -> 0x01)
            (0x01, 0x00, 0x00),  # Slot 10: Unused
            (0x01, 0x00, 0x00),  # Slot 11: Unused
            (0x01, 0x00, 0x00),  # Slot 12: Unused
            (0x01, 0x00, 0x00),  # Slot 13: Unused
            (0x01, 0x00, 0x00),  # Slot 14: Unused
            (0x01, 0x00, 0x00),  # Slot 15: Unused
            (0x0A, 0x00, 0x00),  # Slot 16: Scroll Up (0x0C -> 0x0A)
            (0x09, 0x00, 0x00),  # Slot 17: Scroll Down (0x0B -> 0x09)
        ]

        # UI button index -> hardware slot index:
        # UI 0 (Left) -> Slot 0
        # UI 1 (Right) -> Slot 1
        # UI 2 (Middle) -> Slot 2
        # UI 3 (Forward / Side Front) -> Slot 7
        # UI 4 (Backward / Side Rear) -> Slot 6
        # UI 5 (DPI Cycle) -> Slot 3
        ui_to_slot = [0, 1, 2, 7, 6, 3]
        defaults = [1, 2, 3, 5, 4, 6]
        for ui_idx, slot_idx in enumerate(ui_to_slot):
            act_id = int(button_actions[ui_idx]) if ui_idx < len(button_actions) else defaults[ui_idx]
            slots[slot_idx] = BUTTON_HW_MAP.get(act_id, slots[slot_idx])

        # Safety guard: ensure at least one primary slot retains Left Click (0x02, 0x00, 0x00)
        if (0x02, 0x00, 0x00) not in slots[:8]:
            slots[0] = (0x02, 0x00, 0x00)

        for i, (b0, b1, b2) in enumerate(slots):
            pkt[3 + i * 3 + 0] = b0
            pkt[3 + i * 3 + 1] = b1
            pkt[3 + i * 3 + 2] = b2

        chk = sum(pkt[3:57]) & 0xFFFF
        pkt[57] = (chk >> 8) & 0xFF
        pkt[58] = chk & 0xFF
        return bytes(pkt)


bridge = AttackSharkHardwareBridge()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(BASE_DIR, "dist")
WEB_DIR = DIST_DIR if os.path.isfile(os.path.join(DIST_DIR, "index.html")) else BASE_DIR


class MouseRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def log_message(self, format, *args):
        pass

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/api/status"):
            bridge.discover_devices()
            self._send_json(
                {
                    "connected": bridge.feature_path is not None,
                    "mode": bridge.mode_name,
                    "vid": f"0x{bridge.vid:04X}" if bridge.vid else None,
                    "pid": f"0x{bridge.pid:04X}" if bridge.pid else None,
                    "battery": bridge.battery,
                    "charging": bridge.charging,
                    "sleeping": bridge.sleeping,
                    "activeDpiStage": bridge.active_dpi_stage,
                    "events": bridge.last_events,
                }
            )
            return
        return super().do_GET()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except Exception:
            payload = {}

        if self.path.startswith("/api/query-battery"):
            res = bridge.query_battery()
            self._send_json(
                {
                    "ok": res.get("ok", False),
                    "battery": bridge.battery,
                    "charging": bridge.charging,
                    "sleeping": bridge.sleeping,
                    "activeDpiStage": bridge.active_dpi_stage,
                    "tx": res,
                }
            )
            return

        if self.path.startswith("/api/apply"):
            results = []
            target = payload.get("target", "all")

            # 1. Polling Rate (0x06, 9 bytes)
            if target in ("all", "polling"):
                rate_hz = payload.get("pollingRate", 1000)
                pkt_poll = bridge.build_polling_packet(rate_hz)
                res_poll = bridge.send_feature_packet(pkt_poll)
                res_poll["name"] = f"Polling Rate ({rate_hz} Hz)"
                results.append(res_poll)
                time.sleep(0.04)

            # 2. DPI & Sensor (0x04, 56 bytes)
            if target in ("all", "dpi", "sensor"):
                active_stage = payload.get("activeStage", 1)
                bridge.active_dpi_stage = int(active_stage)
                stages = payload.get("stages", [800, 1600, 2400, 3200, 5000, 26000])
                stage_colors = payload.get("stageColors", None)
                lod = payload.get("lod", 1)
                motion_sync = payload.get("motionSync", False)
                ripple = payload.get("rippleControl", False)
                angle_snap = payload.get("angleSnap", False)

                pkt_dpi = bridge.build_dpi_sensor_packet(
                    active_stage, stages, stage_colors, lod, motion_sync, ripple, angle_snap
                )
                res_dpi = bridge.send_feature_packet(pkt_dpi)
                res_dpi["name"] = f"DPI & Sensor (Stage {int(active_stage)+1}: {stages[int(active_stage)]} DPI)"
                results.append(res_dpi)
                time.sleep(0.04)

            # 3. Key Response Time (Debounce) & Power Sleep Timer (0x05, 15 bytes)
            if target in ("all", "debounce", "power", "sensor", "lighting"):
                debounce = payload.get("debounce", 8)
                sleep_idx = payload.get("sleepMinutes", 1)
                pkt_light = bridge.build_lighting_packet(
                    debounce_ms=debounce,
                    sleep_index=sleep_idx,
                )
                res_light = bridge.send_feature_packet(pkt_light)
                res_light["name"] = f"Key Response Time ({debounce} ms) & Power Management"
                results.append(res_light)
                time.sleep(0.04)

            # 4. Button Mapping (0x08, 59 bytes)
            if target in ("all", "buttons"):
                buttons = payload.get("buttons", [1, 2, 3, 5, 4, 6])
                pkt_btn = bridge.build_buttons_packet(buttons)
                res_btn = bridge.send_feature_packet(pkt_btn)
                res_btn["name"] = "Button Mapping (5 Keys)"
                results.append(res_btn)

            # 5. Windows Mouse Attributes (Pointer Speed, Scroll Speed, Double Click Speed)
            if target in ("mouse_attr",):
                user32 = ctypes.windll.user32
                ptr_speed = max(1, min(20, int(payload.get("pointerSpeed", 10))))
                scroll_lines = max(1, min(20, int(payload.get("scrollLines", 3))))
                dbl_click = max(200, min(900, int(payload.get("doubleClickSpeed", 500))))
                user32.SystemParametersInfoW(0x0071, 0, ctypes.c_void_p(ptr_speed), 2)
                user32.SystemParametersInfoW(0x0069, scroll_lines, None, 2)
                user32.SetDoubleClickTime(dbl_click)
                results.append(
                    {
                        "ok": True,
                        "error_code": 0,
                        "length": 0,
                        "report_id": "OS",
                        "hex": f"Speed={ptr_speed} Scroll={scroll_lines} DblClick={dbl_click}ms",
                        "name": "Mouse Attribute (OS)",
                    }
                )

            all_ok = all(r.get("ok", False) for r in results) if results else False
            self._send_json(
                {
                    "ok": all_ok,
                    "results": results,
                    "battery": bridge.battery,
                    "charging": bridge.charging,
                }
            )
            return

        self._send_json({"ok": False, "error": "Unknown endpoint"}, status=404)


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 3000), MouseRequestHandler)
    print("Attack Shark X3 Native-Web Server running on http://127.0.0.1:3000")
    server.serve_forever()
