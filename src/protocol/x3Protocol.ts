/**
 * Attack Shark X3 Hardware Protocol Specification & Encoder/Decoder
 * Reverse-engineered from X3.exe (0x4132d0..0x414802) and hiddriver_1.dll
 */

export const ATTACK_SHARK_VID = 0x1D57;
export const ATTACK_SHARK_PID_WIRELESS = 0xFA60;
export const ATTACK_SHARK_PID_WIRED = 0xFA61;
export const ATTACK_SHARK_PIDS = [ATTACK_SHARK_PID_WIRELESS, ATTACK_SHARK_PID_WIRED] as const;

export const USAGE_PAGE_EVENT_IN = 0x000A; // col03 (5-byte input report 0x03)
export const USAGE_PAGE_FEATURE = 0x000B;  // col04 (262-byte feature reports 0x04..0x0C)

export type PollingRateHz = 125 | 250 | 500 | 1000;
export type LiftOffDistanceMm = 1 | 2;

export const POLLING_RATE_MAP: Record<PollingRateHz, number> = {
  125: 0x08,
  250: 0x03,
  500: 0x02,
  1000: 0x01
};

export interface ButtonActionOption {
  id: number;
  label: string;
  category: 'Mouse' | 'DPI' | 'Media' | 'Special';
  tuple: readonly [number, number, number];
}

export const BUTTON_ACTION_OPTIONS: readonly ButtonActionOption[] = [
  { id: 1, label: 'Left Click', category: 'Mouse', tuple: [0x02, 0x00, 0x00] },
  { id: 2, label: 'Right Click', category: 'Mouse', tuple: [0x03, 0x00, 0x00] },
  { id: 3, label: 'Middle Button', category: 'Mouse', tuple: [0x04, 0x00, 0x00] },
  { id: 5, label: 'Forward', category: 'Mouse', tuple: [0x05, 0x00, 0x00] },
  { id: 4, label: 'Backward', category: 'Mouse', tuple: [0x06, 0x00, 0x00] },
  { id: 6, label: 'DPI Loop', category: 'DPI', tuple: [0x0D, 0x00, 0x00] },
  { id: 7, label: 'DPI +', category: 'DPI', tuple: [0x0E, 0x00, 0x00] },
  { id: 8, label: 'DPI -', category: 'DPI', tuple: [0x0F, 0x00, 0x00] },
  { id: 9, label: 'Three Click (Fire)', category: 'Special', tuple: [0x10, 0x00, 0x03] },
  { id: 13, label: 'Play / Pause', category: 'Media', tuple: [0x15, 0x00, 0x00] },
  { id: 14, label: 'Next Track', category: 'Media', tuple: [0x1B, 0x00, 0x00] },
  { id: 15, label: 'Previous Track', category: 'Media', tuple: [0x1A, 0x00, 0x00] },
  { id: 10, label: 'Volume +', category: 'Media', tuple: [0x18, 0x00, 0x00] },
  { id: 11, label: 'Volume -', category: 'Media', tuple: [0x19, 0x00, 0x00] },
  { id: 12, label: 'Mute', category: 'Media', tuple: [0x17, 0x00, 0x00] },
  { id: 0, label: 'Disable', category: 'Special', tuple: [0x3C, 0x00, 0x00] }
] as const;

export const BUTTON_HW_MAP: Record<number, readonly [number, number, number]> = Object.fromEntries(
  BUTTON_ACTION_OPTIONS.map((opt) => [opt.id, opt.tuple])
);

export interface DpiSensorConfig {
  activeStage: number; // 0..5 (encoded as 1..6 at pkt[24])
  stages: number[];    // 6 stages, 50..26000 in 50 DPI increments
  stageColors?: string[];
  lod: LiftOffDistanceMm;
  motionSync: boolean;
  rippleControl: boolean;
  angleSnap: boolean;
}

export interface ParsedInputEvent {
  rawHex: string;
  reportId: number;
  messageType: number;
  typeLabel: 'BATTERY_STATUS' | 'DPI_STAGE_CHANGE' | 'POLLING_RATE_SWITCH' | 'SLEEP_STATE' | 'UNKNOWN';
  batteryPercent?: number;
  charging?: boolean;
  activeDpiStage?: number; // 0..5
  sleeping?: boolean;
}

/**
 * Clamp and round a DPI value to valid PAW3395 steps (50..26000, step 50).
 */
export function clampDpiValue(dpi: number): number {
  if (!Number.isFinite(dpi)) return 800;
  const stepped = Math.round(dpi / 50) * 50;
  return Math.max(50, Math.min(26000, stepped));
}

/**
 * Validate that at least one of the 5 primary buttons retains Left Click (id === 1).
 */
export function hasLeftClickAssigned(buttons: readonly number[]): boolean {
  return buttons.slice(0, 5).includes(1);
}

/**
 * Compute 16-bit unsigned sum across buffer[start..end-1].
 */
export function calculateSum16(buffer: Uint8Array, start: number, end: number): number {
  let sum = 0;
  for (let i = start; i < end; i++) {
    sum = (sum + buffer[i]) & 0xFFFF;
  }
  return sum;
}

/**
 * Format Uint8Array as uppercase hex string ("06 09 01 ...").
 */
export function toHexString(bytes: Uint8Array | number[]): string {
  return Array.from(bytes)
    .map((b) => (b & 0xFF).toString(16).toUpperCase().padStart(2, '0'))
    .join(' ');
}

/**
 * Report 0x0C (10 bytes): Battery & Status Query
 */
export function buildQueryStatusPacket(): Uint8Array {
  return new Uint8Array([0x0C, 0x0A, 0x01, 0xFE, 0x01, 0xFE, 0x00, 0x00, 0x00, 0x00]);
}

/**
 * Report 0x06 (9 bytes): Polling Rate (125 / 250 / 500 / 1000 Hz)
 */
export function buildPollingRatePacket(rateHz: PollingRateHz): Uint8Array {
  const code = POLLING_RATE_MAP[rateHz] ?? 0x01;
  const notCode = (~code) & 0xFF;
  return new Uint8Array([0x06, 0x09, 0x01, code, notCode, 0x00, 0x00, 0x00, 0x00]);
}

/**
 * Report 0x04 (56 bytes): DPI Stages, Active Stage (1-based at pkt[24]), LOD, Motion Sync, Angle Snap, Ripple
 * Matches X3.exe 0x414000..0x414316
 */
export function buildDpiSensorPacket(config: DpiSensorConfig): Uint8Array {
  const {
    activeStage = 1,
    stages = [800, 1600, 2400, 3200, 5000, 26000],
    stageColors = ['#ff0000', '#00ff00', '#0000ff', '#ffff00', '#00ffff', '#ff00ff'],
    lod = 1,
    motionSync = false,
    rippleControl = false,
    angleSnap = false
  } = config;

  const pkt = new Uint8Array(56);
  pkt[0] = 0x04;
  pkt[1] = 0x38;
  pkt[2] = 0x01;
  pkt[3] = lod === 2 ? 0x01 : 0x00;
  pkt[4] = motionSync ? 0x01 : 0x00;

  const stageCount = Math.max(1, Math.min(stages.length, 6));
  pkt[5] = (1 << stageCount) - 1; // 0x3F for 6 stages
  pkt[6] = angleSnap ? 0x01 : 0x00;
  pkt[7] = rippleControl ? 0x01 : 0x00;

  for (let i = 0; i < 6; i++) {
    const dpiVal = clampDpiValue(stages[i] ?? 800);
    const stepVal = Math.max(0, Math.floor(dpiVal / 50) - 1);
    pkt[8 + i] = stepVal & 0xFF;
    pkt[16 + i] = (stepVal >> 8) & 0xFF;
  }

  // pkt[24] = 1-based active DPI stage (1..6)
  const clampedActive = Math.max(0, Math.min(5, Math.floor(activeStage)));
  pkt[24] = (clampedActive + 1) & 0xFF;

  const defaultHexColors = [
    '#ff0000', '#00ff00', '#0000ff', '#ffff00',
    '#00ffff', '#ff00ff', '#ff4000', '#ffffff'
  ];

  for (let i = 0; i < 8; i++) {
    const hex = (stageColors[i] || defaultHexColors[i]).replace('#', '');
    pkt[25 + i * 3 + 0] = parseInt(hex.substring(0, 2), 16) || 0;
    pkt[25 + i * 3 + 1] = parseInt(hex.substring(2, 4), 16) || 0;
    pkt[25 + i * 3 + 2] = parseInt(hex.substring(4, 6), 16) || 0;
  }

  pkt[49] = 0x01;
  const chk = calculateSum16(pkt, 3, 50);
  pkt[50] = (chk >> 8) & 0xFF;
  pkt[51] = chk & 0xFF;
  return pkt;
}

/**
 * Report 0x05 (15 bytes): Key Response Time (Debounce) & Sleep Timer
 * Matches X3.exe 0x413db0..0x413e91
 */
export function buildDebounceSleepPacket(debounceMs = 8, sleepIndex = 1): Uint8Array {
  const pkt = new Uint8Array(15);
  pkt[0] = 0x05;
  pkt[1] = 0x0F;
  pkt[2] = 0x01;

  pkt[3] = 0x00;
  pkt[4] = 0x03; // 9 - 6
  pkt[5] = 0xA8; // (10 << 4) | 0x08
  pkt[6] = 0x00;
  pkt[7] = 0x00;
  pkt[8] = 0xFF;
  pkt[9] = Math.max(1, Math.min(30, Math.round(sleepIndex))) & 0xFF;
  pkt[10] = Math.max(1, Math.min(15, Math.round(debounceMs / 2))) & 0xFF;

  const chk = calculateSum16(pkt, 3, 11);
  pkt[11] = (chk >> 8) & 0xFF;
  pkt[12] = chk & 0xFF;
  return pkt;
}

/**
 * Report 0x08 (59 bytes): 18-Slot Hardware Button Mapping Packet
 * Matches X3.exe 0x414600..0x414802 and lookup table 0x41C4AC
 */
export function buildButtonMappingPacket(uiButtons: readonly number[]): Uint8Array {
  const pkt = new Uint8Array(59);
  pkt[0] = 0x08;
  pkt[1] = 0x3B;
  pkt[2] = 0x01;

  // 18 three-byte hardware slots initialized to exact X3.exe defaults (0x41C9E0)
  const slots: [number, number, number][] = [
    [0x02, 0x00, 0x00], // Slot 0: Left Click
    [0x03, 0x00, 0x00], // Slot 1: Right Click
    [0x04, 0x00, 0x00], // Slot 2: Middle Click
    [0x0D, 0x00, 0x00], // Slot 3: Bottom DPI Button (DPI Loop)
    [0x3C, 0x00, 0x00], // Slot 4: Disabled (0x34 -> 0x3C)
    [0x0F, 0x00, 0x00], // Slot 5: DPI - (0x08 -> 0x0F)
    [0x06, 0x00, 0x00], // Slot 6: Side Rear / Backward (0x04 -> 0x06)
    [0x05, 0x00, 0x00], // Slot 7: Side Front / Forward (0x05 -> 0x05)
    [0x3C, 0x00, 0x00], // Slot 8: Disabled (0x34 -> 0x3C)
    [0x01, 0x00, 0x00], // Slot 9: Unused (0x00 -> 0x01)
    [0x01, 0x00, 0x00], // Slot 10: Unused
    [0x01, 0x00, 0x00], // Slot 11: Unused
    [0x01, 0x00, 0x00], // Slot 12: Unused
    [0x01, 0x00, 0x00], // Slot 13: Unused
    [0x01, 0x00, 0x00], // Slot 14: Unused
    [0x01, 0x00, 0x00], // Slot 15: Unused
    [0x0A, 0x00, 0x00], // Slot 16: Scroll Up (0x0C -> 0x0A)
    [0x09, 0x00, 0x00]  // Slot 17: Scroll Down (0x0B -> 0x09)
  ];

  // UI Button [0, 1, 2, 3 (Forward), 4 (Backward), 5 (DPI)] -> Hardware Slots [0, 1, 2, 7, 6, 3]
  const uiToSlot = [0, 1, 2, 7, 6, 3];
  const defaults = [1, 2, 3, 5, 4, 6];

  for (let u = 0; u < uiToSlot.length; u++) {
    const actId = uiButtons[u] ?? defaults[u];
    const tuple = BUTTON_HW_MAP[actId];
    if (tuple) {
      slots[uiToSlot[u]] = [tuple[0], tuple[1], tuple[2]];
    }
  }

  // Hardware safety guard: ensure at least one primary slot (0..7) has Left Click (0x02, 0x00, 0x00)
  const hasPrimaryLeftClick = slots.slice(0, 8).some(
    (s) => s[0] === 0x02 && s[1] === 0x00 && s[2] === 0x00
  );
  if (!hasPrimaryLeftClick) {
    slots[0] = [0x02, 0x00, 0x00];
  }

  for (let i = 0; i < 18; i++) {
    pkt[3 + i * 3 + 0] = slots[i][0];
    pkt[3 + i * 3 + 1] = slots[i][1];
    pkt[3 + i * 3 + 2] = slots[i][2];
  }

  const chk = calculateSum16(pkt, 3, 57);
  pkt[57] = (chk >> 8) & 0xFF;
  pkt[58] = chk & 0xFF;
  return pkt;
}

/**
 * Decode 5-byte Input Report 0x03 from col03 (Matches X3.exe 0x4132d0)
 */
export function parseInputReport03(raw: Uint8Array | number[]): ParsedInputEvent {
  const bytes = Array.from(raw);
  const rawHex = toHexString(bytes);
  if (bytes.length < 5 || bytes[0] !== 0x03) {
    return {
      rawHex,
      reportId: bytes[0] ?? 0,
      messageType: 0,
      typeLabel: 'UNKNOWN'
    };
  }

  const messageType = bytes[1] | (bytes[2] << 8);
  const paramLo = bytes[3];
  const paramHi = bytes[4];

  if (messageType === 0x4010) {
    const level = Math.max(1, Math.min(10, paramHi));
    return {
      rawHex,
      reportId: 0x03,
      messageType,
      typeLabel: 'BATTERY_STATUS',
      batteryPercent: level * 10,
      charging: paramLo === 0,
      sleeping: false
    };
  }

  if (messageType === 0x1000) {
    return {
      rawHex,
      reportId: 0x03,
      messageType,
      typeLabel: 'DPI_STAGE_CHANGE',
      activeDpiStage: Math.max(0, Math.min(5, paramLo - 1))
    };
  }

  if (messageType === 0x2000) {
    return {
      rawHex,
      reportId: 0x03,
      messageType,
      typeLabel: 'POLLING_RATE_SWITCH'
    };
  }

  if (messageType === 0x5010) {
    return {
      rawHex,
      reportId: 0x03,
      messageType,
      typeLabel: 'SLEEP_STATE',
      sleeping: paramLo === 0
    };
  }

  return {
    rawHex,
    reportId: 0x03,
    messageType,
    typeLabel: 'UNKNOWN'
  };
}
/**
 * Hardware Readback Response from /api/read-profile.
 * Mirrors the server.py read_profile() return shape.
 */
export interface ReadProfileResponse {
  source: 'pro.data' | 'defaults';
  profile: import('../transport/types').MouseProfileData;
  proDataAvailable: boolean;
  proDataError: string | null;
  featureReadDiagnostics: FeatureReadDiagnostic[];
  warnings: string[];
}

export interface FeatureReadDiagnostic {
  name: string;
  report_id: string;
  length: number;
  ok: boolean;
  error_code?: number;
  bytes: number[];
  hex: string;
  note?: string;
}

// ── Reverse (Decode) Functions ────────────────────────────────────────────────
//
// These decode the same byte layout encoded by the build* functions above.
// Useful for round-trip tests and for interpreting HidD_GetFeature raw bytes
// (even if they are zeros on write-only firmware, the structure is documented).

/**
 * Decode Report 0x04 (56 bytes) → DpiSensorConfig partial.
 *
 * NOTE: On Attack Shark X3 firmware (PAW3395) HidD_GetFeature returns zeros for
 * this report (write-only col04). These decoders are provided for round-trip
 * testing and for any future firmware that does support readback.
 */
export function decodeDpiSensorPacket(pkt: Uint8Array): {
  lod: LiftOffDistanceMm;
  motionSync: boolean;
  angleSnap: boolean;
  rippleControl: boolean;
  stages: number[];
  activeStage: number; // 0-based
  stageColors: string[];
} {
  if (pkt.length < 52) throw new RangeError(`Report 0x04 must be ≥52 bytes, got ${pkt.length}`);
  if (pkt[0] !== 0x04) throw new Error(`Expected report ID 0x04, got 0x${pkt[0].toString(16)}`);

  const lod: LiftOffDistanceMm = pkt[3] === 0x01 ? 2 : 1;
  const motionSync = pkt[4] !== 0;
  const angleSnap = pkt[6] !== 0;
  const rippleControl = pkt[7] !== 0;

  const stages: number[] = [];
  for (let i = 0; i < 6; i++) {
    const lo = pkt[8 + i];
    const hi = pkt[16 + i];
    const step = lo | (hi << 8);
    stages.push(clampDpiValue((step + 1) * 50));
  }

  // pkt[24] = 1-based active DPI stage (1..6); convert to 0-based
  const activeStage = Math.max(0, Math.min(5, (pkt[24] & 0xFF) - 1));

  const stageColors: string[] = [];
  for (let i = 0; i < 6; i++) {
    const r = pkt[25 + i * 3];
    const g = pkt[25 + i * 3 + 1];
    const b = pkt[25 + i * 3 + 2];
    stageColors.push(`#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`);
  }

  return { lod, motionSync, angleSnap, rippleControl, stages, activeStage, stageColors };
}

/**
 * Decode Report 0x05 (15 bytes) → debounce ms and sleep timer index.
 */
export function decodeDebounceSleepPacket(pkt: Uint8Array): {
  debounceMs: number;
  sleepIndex: number;
} {
  if (pkt.length < 11) throw new RangeError(`Report 0x05 must be ≥11 bytes, got ${pkt.length}`);
  if (pkt[0] !== 0x05) throw new Error(`Expected report ID 0x05, got 0x${pkt[0].toString(16)}`);

  // pkt[10] = debounce_ms / 2  →  debounce_ms = pkt[10] * 2, clamped to [2..20]
  const debounceMs = Math.max(2, Math.min(20, (pkt[10] & 0xFF) * 2));
  // pkt[9] = sleep index (1..30)
  const sleepIndex = Math.max(1, Math.min(30, pkt[9] & 0xFF));
  return { debounceMs, sleepIndex };
}

/**
 * Decode Report 0x06 (9 bytes) → polling rate in Hz.
 */
export function decodePollingRatePacket(pkt: Uint8Array): PollingRateHz {
  if (pkt.length < 5) throw new RangeError(`Report 0x06 must be ≥5 bytes, got ${pkt.length}`);
  if (pkt[0] !== 0x06) throw new Error(`Expected report ID 0x06, got 0x${pkt[0].toString(16)}`);

  const codeToHz: Record<number, PollingRateHz> = {
    0x01: 1000,
    0x02: 500,
    0x03: 250,
    0x08: 125
  };
  return codeToHz[pkt[3]] ?? 1000;
}

/** Reverse lookup: hardware 3-byte tuple → action ID (or undefined if unknown). */
const HW_TUPLE_TO_ID: Map<string, number> = new Map(
  BUTTON_ACTION_OPTIONS.map((opt) => [opt.tuple.join(','), opt.id])
);

/**
 * Decode Report 0x08 (59 bytes) → 5-element UI button action ID array.
 *
 * Hardware slot → UI index mapping (inverse of buildButtonMappingPacket):
 *   Slot 0 → UI 0 (Left)
 *   Slot 1 → UI 1 (Right)
 *   Slot 2 → UI 2 (Middle)
 *   Slot 7 → UI 3 (Forward)
 *   Slot 6 → UI 4 (Backward)
 */
export function decodeButtonMappingPacket(pkt: Uint8Array): number[] {
  if (pkt.length < 57) throw new RangeError(`Report 0x08 must be ≥57 bytes, got ${pkt.length}`);
  if (pkt[0] !== 0x08) throw new Error(`Expected report ID 0x08, got 0x${pkt[0].toString(16)}`);

  const defaults = [1, 2, 3, 5, 4];
  // Hardware slot indices for UI buttons [Left, Right, Middle, Forward, Backward]
  const slotToUi: [number, number][] = [[0, 0], [1, 1], [2, 2], [7, 3], [6, 4]];
  const result = [...defaults];

  for (const [slotIdx, uiIdx] of slotToUi) {
    const b0 = pkt[3 + slotIdx * 3];
    const b1 = pkt[3 + slotIdx * 3 + 1];
    const b2 = pkt[3 + slotIdx * 3 + 2];
    const key = `${b0},${b1},${b2}`;
    const actionId = HW_TUPLE_TO_ID.get(key);
    if (actionId !== undefined) {
      result[uiIdx] = actionId;
    }
  }

  return result;
}
