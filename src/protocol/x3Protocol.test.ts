import { describe, it, expect } from 'vitest';
import {
  buildQueryStatusPacket,
  buildPollingRatePacket,
  buildDpiSensorPacket,
  buildDebounceSleepPacket,
  buildButtonMappingPacket,
  parseInputReport03,
  clampDpiValue,
  hasLeftClickAssigned,
  toHexString,
  decodeDpiSensorPacket,
  decodeDebounceSleepPacket,
  decodePollingRatePacket,
  decodeButtonMappingPacket,
  PollingRateHz
} from './x3Protocol';


describe('Attack Shark X3 Protocol Suite (Verified against X3.exe)', () => {
  it('encodes Report 0x0C (10-byte status/battery query) identically to X3.exe 0x4132b0', () => {
    const pkt = buildQueryStatusPacket();
    expect(pkt.length).toBe(10);
    expect(toHexString(pkt)).toBe('0C 0A 01 FE 01 FE 00 00 00 00');
  });

  it('encodes Report 0x06 (9-byte polling rate) with bitwise complement verification', () => {
    expect(toHexString(buildPollingRatePacket(1000))).toBe('06 09 01 01 FE 00 00 00 00');
    expect(toHexString(buildPollingRatePacket(500))).toBe('06 09 01 02 FD 00 00 00 00');
    expect(toHexString(buildPollingRatePacket(250))).toBe('06 09 01 03 FC 00 00 00 00');
    expect(toHexString(buildPollingRatePacket(125))).toBe('06 09 01 08 F7 00 00 00 00');
  });

  it('encodes Report 0x04 (56-byte DPI & Sensor packet) identically to X3.exe 0x414000', () => {
    const pkt = buildDpiSensorPacket({
      activeStage: 1, // Stage 2 (1600 DPI) -> pkt[24] = 0x02
      stages: [800, 1600, 2400, 3200, 5000, 26000],
      lod: 1,
      motionSync: false,
      rippleControl: false,
      angleSnap: false
    });
    expect(pkt.length).toBe(56);
    expect(toHexString(pkt)).toBe(
      '04 38 01 00 00 3F 00 00 0F 1F 2F 3F 63 07 00 00 00 00 00 00 00 02 00 00 02 ' +
      'FF 00 00 00 FF 00 00 00 FF FF FF 00 00 FF FF FF 00 FF FF 40 00 FF FF FF 01 0E 7D 00 00 00 00'
    );
  });

  it('encodes Report 0x04 sensor flags (LOD=2mm, MotionSync=On, AngleSnap=On, Ripple=On)', () => {
    const pkt = buildDpiSensorPacket({
      activeStage: 0,
      stages: [800, 1600, 2400, 3200, 5000, 26000],
      lod: 2,
      motionSync: true,
      angleSnap: true,
      rippleControl: true
    });
    expect(pkt[3]).toBe(0x01); // LOD 2mm
    expect(pkt[4]).toBe(0x01); // Motion Sync On
    expect(pkt[6]).toBe(0x01); // Angle Snap On
    expect(pkt[7]).toBe(0x01); // Ripple Control On
    expect(pkt[24]).toBe(0x01); // Stage 1 (1-based)
  });

  it('encodes Report 0x05 (15-byte Key Response Time & Sleep packet) identically to X3.exe 0x413db0', () => {
    const pkt = buildDebounceSleepPacket(8, 1);
    expect(pkt.length).toBe(15);
    expect(toHexString(pkt)).toBe('05 0F 01 00 03 A8 00 00 FF 01 04 01 AF 00 00');
  });

  it('encodes Report 0x08 (59-byte 18-slot Button Mapping packet) identically to X3.exe 0x414600', () => {
    const pkt = buildButtonMappingPacket([1, 2, 3, 5, 4, 6]);
    expect(pkt.length).toBe(59);
    expect(toHexString(pkt)).toBe(
      '08 3B 01 02 00 00 03 00 00 04 00 00 0D 00 00 3C 00 00 0F 00 00 06 00 00 05 00 00 ' +
      '3C 00 00 01 00 00 01 00 00 01 00 00 01 00 00 01 00 00 01 00 00 01 00 00 0A 00 00 09 00 00 00 C2'
    );
  });

  it('enforces hardware safety guard so Left Click (0x02, 0x00, 0x00) is never lost', () => {
    expect(hasLeftClickAssigned([0, 2, 3, 5, 4])).toBe(false);
    expect(hasLeftClickAssigned([2, 1, 3, 5, 4])).toBe(true);

    // Even if all disabled buttons are passed, buildButtonMappingPacket forces Slot 0 = 02 00 00
    const pkt = buildButtonMappingPacket([0, 0, 0, 0, 0]);
    expect(pkt[3]).toBe(0x02);
    expect(pkt[4]).toBe(0x00);
    expect(pkt[5]).toBe(0x00);
  });

  it('decodes 5-byte Input Report 0x03 from col03 (battery, DPI button, sleep state)', () => {
    const bat = parseInputReport03([0x03, 0x10, 0x40, 0x01, 0x09]);
    expect(bat.typeLabel).toBe('BATTERY_STATUS');
    expect(bat.batteryPercent).toBe(90);
    expect(bat.charging).toBe(false);

    const chg = parseInputReport03([0x03, 0x10, 0x40, 0x00, 0x0A]);
    expect(chg.batteryPercent).toBe(100);
    expect(chg.charging).toBe(true);

    const dpiEvt = parseInputReport03([0x03, 0x00, 0x10, 0x03, 0x00]);
    expect(dpiEvt.typeLabel).toBe('DPI_STAGE_CHANGE');
    expect(dpiEvt.activeDpiStage).toBe(2); // 0-based index for stage 3

    const slpEvt = parseInputReport03([0x03, 0x10, 0x50, 0x00, 0x00]);
    expect(slpEvt.typeLabel).toBe('SLEEP_STATE');
    expect(slpEvt.sleeping).toBe(true);
  });

  it('clamps and rounds DPI values to 50-DPI PAW3395 steps between 50 and 26000', () => {
    expect(clampDpiValue(10)).toBe(50);
    expect(clampDpiValue(29000)).toBe(26000);
    expect(clampDpiValue(1624)).toBe(1600);
    expect(clampDpiValue(1626)).toBe(1650);
  });

  describe('Hardware Readback Decoding & Round-Trip', () => {
    it('round-trips Report 0x06 (polling rate): encode -> decode matches', () => {
      const rates: PollingRateHz[] = [125, 250, 500, 1000];
      for (const hz of rates) {
        const pkt = buildPollingRatePacket(hz);
        const decoded = decodePollingRatePacket(pkt);
        expect(decoded).toBe(hz);
      }
    });

    it('round-trips Report 0x05 (debounce & sleep): encode -> decode matches', () => {
      const testCases = [
        { debounce: 4, sleep: 1 },
        { debounce: 8, sleep: 5 },
        { debounce: 12, sleep: 15 },
        { debounce: 20, sleep: 30 }
      ];

      for (const tc of testCases) {
        const pkt = buildDebounceSleepPacket(tc.debounce, tc.sleep);
        const decoded = decodeDebounceSleepPacket(pkt);
        expect(decoded.debounceMs).toBe(tc.debounce);
        expect(decoded.sleepIndex).toBe(tc.sleep);
      }
    });

    it('round-trips Report 0x04 (DPI & sensor): encode -> decode matches', () => {
      const inputConfig = {
        activeStage: 2, // Stage 3
        stages: [400, 800, 1600, 3200, 6400, 26000],
        stageColors: ['#ff0000', '#00ff00', '#0000ff', '#ffff00', '#00ffff', '#ff00ff'],
        lod: 2 as const,
        motionSync: true,
        rippleControl: true,
        angleSnap: true
      };

      const pkt = buildDpiSensorPacket(inputConfig);
      const decoded = decodeDpiSensorPacket(pkt);

      expect(decoded.activeStage).toBe(2);
      expect(decoded.stages).toEqual(inputConfig.stages);
      expect(decoded.lod).toBe(2);
      expect(decoded.motionSync).toBe(true);
      expect(decoded.rippleControl).toBe(true);
      expect(decoded.angleSnap).toBe(true);
      expect(decoded.stageColors).toEqual(inputConfig.stageColors);
    });

    it('round-trips Report 0x08 (button mapping): encode -> decode matches 5 primary buttons', () => {
      // Buttons: Left(1), Right(2), Middle(3), Forward(5), Backward(4)
      const buttons = [1, 2, 3, 5, 4];
      const pkt = buildButtonMappingPacket([...buttons, 6]);
      const decoded = decodeButtonMappingPacket(pkt);
      expect(decoded).toEqual(buttons);
    });

    it('round-trips custom button mappings through Report 0x08', () => {
      // Custom: Left(1), Right(2), Middle(10=Vol+), Forward(11=Vol-), Backward(12=Mute)
      const customButtons = [1, 2, 10, 11, 12];
      const pkt = buildButtonMappingPacket([...customButtons, 6]);
      const decoded = decodeButtonMappingPacket(pkt);
      expect(decoded).toEqual(customButtons);
    });

    it('handles truncated or invalid packets safely', () => {
      expect(() => decodeDpiSensorPacket(new Uint8Array([0x04, 0x01]))).toThrow(RangeError);
      expect(() => decodeDebounceSleepPacket(new Uint8Array([0x05, 0x01]))).toThrow(RangeError);
      expect(() => decodePollingRatePacket(new Uint8Array([0x06]))).toThrow(RangeError);
      expect(() => decodeButtonMappingPacket(new Uint8Array([0x08]))).toThrow(RangeError);
    });
  });
});

