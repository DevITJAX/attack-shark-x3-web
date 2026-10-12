/**
 * Attack Shark X3 Hardware Protocol Library
 * Exact byte-for-byte implementation reverse-engineered from X3.exe & hiddriver_1.dll
 *
 * Packet Summary:
 * - 0x06 (9 bytes):  Polling Rate [0x06, 0x09, 0x01, code, ~code, 0, 0, 0, 0]
 * - 0x04 (56 bytes): DPI Stages ((DPI/50)-1), Active Stage, LOD, Ripple, AngleSnap, Debounce, Stage RGB, Big-Endian Sum16
 * - 0x05 (15 bytes): RGB Lighting, Brightness, Speed, Motion Sync, Sleep Timer, Big-Endian Sum16
 * - 0x08 (59 bytes): 6-Button Hardware Action Table, Big-Endian Sum16
 * - 0x0C (10 bytes): Battery & Status Query [0x0C, 0x0A, 0x01, 0xFE, 0x01, 0xFE, 0, 0, 0, 0]
 */

const ATTACK_SHARK_VID = 0x1D57;
const ATTACK_SHARK_PIDS = [0xFA60, 0xFA61];

const POLLING_RATE_MAP = {
  125:  0x08,
  250:  0x03,
  500:  0x02,
  1000: 0x01
};

const BUTTON_HW_MAP = {
  1:  [0x02, 0x00, 0x00], // Left Click
  2:  [0x03, 0x00, 0x00], // Right Click
  3:  [0x04, 0x00, 0x00], // Middle Click
  4:  [0x06, 0x00, 0x00], // Backward
  5:  [0x05, 0x00, 0x00], // Forward
  6:  [0x0D, 0x00, 0x00], // DPI Cycle (Loop)
  7:  [0x0E, 0x00, 0x00], // DPI +
  8:  [0x0F, 0x00, 0x00], // DPI -
  9:  [0x10, 0x00, 0x03], // Fire / Triple Click
  10: [0x18, 0x00, 0x00], // Volume Up
  11: [0x19, 0x00, 0x00], // Volume Down
  12: [0x17, 0x00, 0x00], // Mute
  0:  [0x3C, 0x00, 0x00]  // Disabled
};

function calculateSum16(buffer, start, end) {
  let sum = 0;
  for (let i = start; i < end; i++) {
    sum = (sum + buffer[i]) & 0xFFFF;
  }
  return sum;
}

function buildPollingRatePacket(rateHz) {
  const code = POLLING_RATE_MAP[rateHz] || 0x01;
  const notCode = (~code) & 0xFF;
  const packet = new Uint8Array(9);
  packet[0] = 0x06;
  packet[1] = 0x09;
  packet[2] = 0x01;
  packet[3] = code;
  packet[4] = notCode;
  return packet;
}

function buildDpiSensorPacket(options) {
  const {
    activeStage = 1,
    stages = [800, 1600, 2400, 3200, 5000, 26000],
    stageColors = ['#ff0000', '#00ff00', '#0000ff', '#ffff00', '#00ffff', '#ff00ff'],
    lod = 1,
    motionSync = false,
    rippleControl = false,
    angleSnap = false
  } = options;

  const pkt = new Uint8Array(56);
  pkt[0] = 0x04;
  pkt[1] = 0x38;
  pkt[2] = 0x01;
  pkt[3] = lod === 2 ? 0x01 : 0x00;
  pkt[4] = motionSync ? 0x01 : 0x00;
  pkt[5] = (1 << Math.min(stages.length, 6)) - 1;
  pkt[6] = angleSnap ? 0x01 : 0x00;
  pkt[7] = rippleControl ? 0x01 : 0x00;

  for (let i = 0; i < 6; i++) {
    const dpiVal = Math.max(50, Math.min(26000, stages[i] || 800));
    const stepVal = Math.max(0, Math.floor(dpiVal / 50) - 1);
    pkt[8 + i] = stepVal & 0xFF;
    pkt[16 + i] = (stepVal >> 8) & 0xFF;
  }

  pkt[24] = (Math.max(0, Math.min(5, activeStage)) + 1) & 0xFF;

  for (let i = 0; i < 8; i++) {
    const hex = (stageColors[i] || '#ff0000').replace('#', '');
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

function buildLightingPacket(debounceMs = 8, sleepIndex = 1) {
  const pkt = new Uint8Array(15);
  pkt[0] = 0x05;
  pkt[1] = 0x0F;
  pkt[2] = 0x01;

  pkt[3] = 0x00;
  pkt[4] = 0x03;
  pkt[5] = 0xA8;
  pkt[6] = 0x00;
  pkt[7] = 0x00;
  pkt[8] = 0xFF;
  pkt[9] = Math.max(1, Math.min(30, sleepIndex)) & 0xFF;
  pkt[10] = Math.max(1, Math.min(15, Math.round(debounceMs / 2))) & 0xFF;

  const chk = calculateSum16(pkt, 3, 11);
  pkt[11] = (chk >> 8) & 0xFF;
  pkt[12] = chk & 0xFF;
  return pkt;
}

function buildButtonMappingPacket(buttonActions) {
  const pkt = new Uint8Array(59);
  pkt[0] = 0x08;
  pkt[1] = 0x3B;
  pkt[2] = 0x01;

  const slots = [
    [0x02, 0x00, 0x00], // Slot 0: Left Click
    [0x03, 0x00, 0x00], // Slot 1: Right Click
    [0x04, 0x00, 0x00], // Slot 2: Middle Click
    [0x0D, 0x00, 0x00], // Slot 3: DPI Cycle
    [0x3C, 0x00, 0x00], // Slot 4: Disabled
    [0x0F, 0x00, 0x00], // Slot 5: DPI -
    [0x06, 0x00, 0x00], // Slot 6: Backward
    [0x05, 0x00, 0x00], // Slot 7: Forward
    [0x3C, 0x00, 0x00], // Slot 8: Disabled
    [0x01, 0x00, 0x00], // Slot 9..15: Unused
    [0x01, 0x00, 0x00],
    [0x01, 0x00, 0x00],
    [0x01, 0x00, 0x00],
    [0x01, 0x00, 0x00],
    [0x01, 0x00, 0x00],
    [0x01, 0x00, 0x00],
    [0x0A, 0x00, 0x00], // Slot 16: Scroll Up
    [0x09, 0x00, 0x00]  // Slot 17: Scroll Down
  ];

  const uiToSlot = [0, 1, 2, 7, 6, 3];
  const defaults = [1, 2, 3, 5, 4, 6];
  for (let u = 0; u < uiToSlot.length; u++) {
    const act = buttonActions[u] ?? defaults[u];
    slots[uiToSlot[u]] = BUTTON_HW_MAP[act] || slots[uiToSlot[u]];
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

function buildQueryStatusPacket() {
  return new Uint8Array([0x0C, 0x0A, 0x01, 0xFE, 0x01, 0xFE, 0x00, 0x00, 0x00, 0x00]);
}

window.AttackSharkProtocol = {
  ATTACK_SHARK_VID,
  ATTACK_SHARK_PIDS,
  buildPollingRatePacket,
  buildLightingPacket,
  buildDpiSensorPacket,
  buildButtonMappingPacket,
  buildQueryStatusPacket
};
