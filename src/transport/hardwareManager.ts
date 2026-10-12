import {
  ATTACK_SHARK_PID_WIRED,
  ATTACK_SHARK_PID_WIRELESS,
  ATTACK_SHARK_VID,
  USAGE_PAGE_EVENT_IN,
  USAGE_PAGE_FEATURE,
  buildButtonMappingPacket,
  buildDebounceSleepPacket,
  buildDpiSensorPacket,
  buildPollingRatePacket,
  buildQueryStatusPacket,
  parseInputReport03,
  toHexString
} from '../protocol/x3Protocol';
import {
  ApplyTarget,
  DeviceStatus,
  HidCollectionSummary,
  MouseProfileData,
  PacketResultItem,
  TransportKind
} from './types';

export interface ApplyResponse {
  ok: boolean;
  results: PacketResultItem[];
  batteryPercent?: number;
  charging?: boolean;
  errorMessage?: string;
}

/**
 * Hardware Abstraction Layer supporting:
 * 1. Local Native Bridge (`server.py` using Win32 `HidD_SetFeature` on `col04` & `ReadFile` on `col03`)
 * 2. Browser WebHID (`navigator.hid` with collection capability inspection)
 * 3. Mock Hardware Simulation (for offline testing and development)
 */
export class AttackSharkHardwareManager {
  private mode: TransportKind = 'bridge';
  private webHidDevices: any[] = [];
  private mockBattery = 90;
  private mockCharging = false;
  private mockActiveStage = 1;
  private onAsyncEvent?: (evt: { summary: string; hex: string; battery?: number; charging?: boolean; stage?: number }) => void;

  constructor(onAsyncEvent?: (evt: { summary: string; hex: string; battery?: number; charging?: boolean; stage?: number }) => void) {
    this.onAsyncEvent = onAsyncEvent;
  }

  public setTransportMode(mode: TransportKind): void {
    this.mode = mode;
  }

  public getTransportMode(): TransportKind {
    return this.mode;
  }

  public isWebHidAvailable(): boolean {
    return typeof navigator !== 'undefined' && 'hid' in navigator;
  }

  /**
   * Request explicit user permission via Browser WebHID (`navigator.hid.requestDevice`)
   * filtered strictly to Attack Shark X3 (`VID=0x1D57, PID=0xFA60 | 0xFA61`).
   */
  public async connectWebHid(): Promise<{ ok: boolean; status: DeviceStatus; message: string }> {
    if (!this.isWebHidAvailable()) {
      return {
        ok: false,
        status: await this.getStatus(),
        message: 'WebHID API is not supported in this browser (use Chrome or Edge).'
      };
    }

    try {
      const navHid = (navigator as any).hid;
      const selected: any[] = await navHid.requestDevice({
        filters: [
          { vendorId: ATTACK_SHARK_VID, productId: ATTACK_SHARK_PID_WIRELESS },
          { vendorId: ATTACK_SHARK_VID, productId: ATTACK_SHARK_PID_WIRED }
        ]
      });

      if (!selected || selected.length === 0) {
        return {
          ok: false,
          status: await this.getStatus(),
          message: 'No Attack Shark X3 device selected in chooser.'
        };
      }

      const allAuthorized: any[] = await navHid.getDevices();
      this.webHidDevices = allAuthorized.filter(
        (d) =>
          d.vendorId === ATTACK_SHARK_VID &&
          (d.productId === ATTACK_SHARK_PID_WIRELESS || d.productId === ATTACK_SHARK_PID_WIRED)
      );

      for (const dev of this.webHidDevices) {
        if (!dev.opened) {
          try {
            await dev.open();
          } catch (_) {}
        }
        dev.oninputreport = (event: any) => {
          const bytes = new Uint8Array(event.data.buffer);
          const full = new Uint8Array(bytes.length + 1);
          full[0] = event.reportId;
          full.set(bytes, 1);
          const parsed = parseInputReport03(full);
          if (this.onAsyncEvent) {
            this.onAsyncEvent({
              summary: `WebHID Input Report (${parsed.typeLabel})`,
              hex: parsed.rawHex,
              battery: parsed.batteryPercent,
              charging: parsed.charging,
              stage: parsed.activeDpiStage
            });
          }
        };
      }

      this.mode = 'webhid';
      const status = await this.getStatus();
      const warning = status.webHidFeatureWriteBlocked
        ? 'Connected via WebHID (Note: Windows HID descriptor has 0 Feature ValueCaps on col04; use Native Bridge mode to write settings on Windows).'
        : 'Connected via WebHID.';
      return { ok: true, status, message: warning };
    } catch (err: any) {
      return {
        ok: false,
        status: await this.getStatus(),
        message: err?.message || 'WebHID connection failed.'
      };
    }
  }

  public async getStatus(): Promise<DeviceStatus> {
    const webHidSupported = this.isWebHidAvailable();

    if (this.mode === 'mock') {
      return {
        connected: true,
        transportKind: 'mock',
        deviceName: 'Attack Shark X3 (Simulated PAW3395)',
        connectionMode: 'Simulated 2.4GHz Wireless (PID 0xFA60)',
        vid: '0x1D57',
        pid: '0xFA60',
        batteryPercent: this.mockBattery,
        charging: this.mockCharging,
        sleeping: false,
        activeDpiStage: this.mockActiveStage,
        webHidSupported
      };
    }

    if (this.mode === 'webhid') {
      const collections: HidCollectionSummary[] = [];
      let featureCapable = false;
      let pidNum: number | null = null;

      for (const dev of this.webHidDevices) {
        pidNum = dev.productId;
        for (const col of dev.collections || []) {
          const fReps = (col.featureReports || []).map((r: any) => r.reportId);
          if (col.usagePage === USAGE_PAGE_FEATURE && fReps.length > 0) {
            featureCapable = true;
          }
          collections.push({
            usagePage: `0x${(col.usagePage || 0).toString(16).toUpperCase().padStart(4, '0')}`,
            usage: `0x${(col.usage || 0).toString(16).toUpperCase().padStart(4, '0')}`,
            inputReports: (col.inputReports || []).map((r: any) => r.reportId),
            outputReports: (col.outputReports || []).map((r: any) => r.reportId),
            featureReports: fReps
          });
        }
      }

      return {
        connected: this.webHidDevices.length > 0,
        transportKind: 'webhid',
        deviceName: 'Attack Shark X3',
        connectionMode:
          pidNum === ATTACK_SHARK_PID_WIRED
            ? 'WebHID USB Wired (0xFA61)'
            : 'WebHID 2.4GHz Wireless (0xFA60)',
        vid: this.webHidDevices.length > 0 ? '0x1D57' : null,
        pid: pidNum ? `0x${pidNum.toString(16).toUpperCase()}` : null,
        batteryPercent: this.mockBattery,
        charging: this.mockCharging,
        sleeping: false,
        activeDpiStage: this.mockActiveStage,
        webHidSupported,
        webHidFeatureWriteBlocked: this.webHidDevices.length > 0 && !featureCapable,
        collections
      };
    }

    // Default: Native Bridge (`server.py` on local port 3000)
    const bridgeBase =
      typeof window !== 'undefined' &&
      window.location.port !== '3000' &&
      window.location.port !== '5173'
        ? 'http://127.0.0.1:3000'
        : '';
    try {
      const resp = await fetch(`${bridgeBase}/api/status`);
      const data = await resp.json();
      return {
        connected: Boolean(data.connected),
        transportKind: 'bridge',
        deviceName: 'Attack Shark X3 (PAW3395)',
        connectionMode: data.mode || 'Disconnected',
        vid: data.vid || null,
        pid: data.pid || null,
        batteryPercent: typeof data.battery === 'number' ? data.battery : 90,
        charging: Boolean(data.charging),
        sleeping: Boolean(data.sleeping),
        activeDpiStage: typeof data.activeDpiStage === 'number' ? data.activeDpiStage : 1,
        webHidSupported
      };
    } catch (_) {
      return {
        connected: false,
        transportKind: 'bridge',
        deviceName: 'Attack Shark X3',
        connectionMode: 'Bridge Offline (Run server.py or switch to Mock/WebHID)',
        vid: null,
        pid: null,
        batteryPercent: 0,
        charging: false,
        sleeping: false,
        activeDpiStage: 1,
        webHidSupported
      };
    }
  }

  public async queryBattery(): Promise<{ ok: boolean; batteryPercent: number; charging: boolean; hex: string }> {
    const pkt = buildQueryStatusPacket();
    const hex = toHexString(pkt);
    const bridgeBase =
      typeof window !== 'undefined' &&
      window.location.port !== '3000' &&
      window.location.port !== '5173'
        ? 'http://127.0.0.1:3000'
        : '';

    if (this.mode === 'mock') {
      return {
        ok: true,
        batteryPercent: this.mockBattery,
        charging: this.mockCharging,
        hex
      };
    }

    if (this.mode === 'bridge') {
      try {
        const resp = await fetch(`${bridgeBase}/api/query-battery`, { method: 'POST' });
        const data = await resp.json();
        return {
          ok: Boolean(data.ok),
          batteryPercent: typeof data.battery === 'number' ? data.battery : 90,
          charging: Boolean(data.charging),
          hex: data.tx?.hex || hex
        };
      } catch (_) {
        return { ok: false, batteryPercent: 0, charging: false, hex };
      }
    }

    // WebHID attempt
    return { ok: false, batteryPercent: this.mockBattery, charging: this.mockCharging, hex };
  }

  public async applyConfiguration(target: ApplyTarget, profile: MouseProfileData): Promise<ApplyResponse> {
    const buttonsWithDpi = [...profile.buttons.slice(0, 5), 6];
    const bridgeBase =
      typeof window !== 'undefined' &&
      window.location.port !== '3000' &&
      window.location.port !== '5173'
        ? 'http://127.0.0.1:3000'
        : '';

    // 1. Native Bridge Mode (`server.py`)
    if (this.mode === 'bridge') {
      try {
        const resp = await fetch(`${bridgeBase}/api/apply`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target,
            activeStage: profile.activeStage,
            stages: profile.stages,
            stageColors: profile.stageColors,
            pollingRate: profile.pollingRate,
            lod: profile.lod,
            debounce: profile.debounce,
            rippleControl: profile.rippleControl,
            angleSnap: profile.angleSnap,
            motionSync: profile.motionSync,
            sleepMinutes: profile.sleepMinutes,
            pointerSpeed: profile.pointerSpeed,
            doubleClickSpeed: profile.doubleClickSpeed,
            scrollLines: profile.scrollLines,
            buttons: buttonsWithDpi
          })
        });
        const data = await resp.json();
        const results: PacketResultItem[] = (data.results || []).map((r: any) => ({
          name: r.name,
          reportId: r.report_id,
          length: r.length,
          hex: r.hex,
          ok: Boolean(r.ok),
          errorCode: r.error_code,
          simulated: false
        }));
        return {
          ok: Boolean(data.ok),
          results,
          batteryPercent: data.battery,
          charging: data.charging
        };
      } catch (err: any) {
        return {
          ok: false,
          results: [],
          errorMessage: 'Local hardware bridge (server.py) is unreachable.'
        };
      }
    }

    // Build exact packets in TypeScript for Mock or WebHID modes
    const packets: { name: string; bytes: Uint8Array }[] = [];

    if (target === 'all' || target === 'polling') {
      packets.push({
        name: `Polling Rate (${profile.pollingRate} Hz)`,
        bytes: buildPollingRatePacket(profile.pollingRate)
      });
    }

    if (target === 'all' || target === 'dpi' || target === 'sensor') {
      packets.push({
        name: `DPI & Sensor (Stage ${profile.activeStage + 1}: ${profile.stages[profile.activeStage]} DPI)`,
        bytes: buildDpiSensorPacket({
          activeStage: profile.activeStage,
          stages: profile.stages,
          stageColors: profile.stageColors,
          lod: profile.lod,
          motionSync: profile.motionSync,
          rippleControl: profile.rippleControl,
          angleSnap: profile.angleSnap
        })
      });
    }

    if (target === 'all' || target === 'debounce' || target === 'power' || target === 'sensor') {
      packets.push({
        name: `Key Response Time (${profile.debounce} ms) & Sleep Timer`,
        bytes: buildDebounceSleepPacket(profile.debounce, profile.sleepMinutes)
      });
    }

    if (target === 'all' || target === 'buttons') {
      packets.push({
        name: 'Button Mapping (18-Slot Table)',
        bytes: buildButtonMappingPacket(buttonsWithDpi)
      });
    }

    // 2. Mock Mode (Simulated Hardware)
    if (this.mode === 'mock') {
      this.mockActiveStage = profile.activeStage;
      const results: PacketResultItem[] = packets.map((p) => ({
        name: `[SIMULATED] ${p.name}`,
        reportId: `0x${p.bytes[0].toString(16).toUpperCase().padStart(2, '0')}`,
        length: p.bytes.length,
        hex: toHexString(p.bytes),
        ok: true,
        simulated: true
      }));
      return {
        ok: true,
        results,
        batteryPercent: this.mockBattery,
        charging: this.mockCharging
      };
    }

    // 3. Direct Browser WebHID Mode
    const featDev = this.webHidDevices.find((d) =>
      (d.collections || []).some((c: any) => c.usagePage === USAGE_PAGE_FEATURE)
    );

    const results: PacketResultItem[] = [];
    for (const p of packets) {
      const reportId = p.bytes[0];
      const payload = p.bytes.slice(1);
      try {
        if (!featDev) {
          throw new Error('Feature interface (UsagePage 0x000B) not open in WebHID');
        }
        await featDev.sendFeatureReport(reportId, payload);
        results.push({
          name: p.name,
          reportId: `0x${reportId.toString(16).toUpperCase().padStart(2, '0')}`,
          length: p.bytes.length,
          hex: toHexString(p.bytes),
          ok: true,
          simulated: false
        });
      } catch (err: any) {
        results.push({
          name: `${p.name} — Blocked by Windows WebHID (Use Native Bridge)`,
          reportId: `0x${reportId.toString(16).toUpperCase().padStart(2, '0')}`,
          length: p.bytes.length,
          hex: toHexString(p.bytes),
          ok: false,
          simulated: false
        });
      }
    }

    const allOk = results.length > 0 && results.every((r) => r.ok);
    return {
      ok: allOk,
      results,
      errorMessage: allOk
        ? undefined
        : 'Windows WebHID blocked sendFeatureReport because UsagePage 0x000B has Usage 0x0000 (0 ValueCaps). Switch Transport to "Native Bridge" for verified hardware writes.'
    };
  }
}
