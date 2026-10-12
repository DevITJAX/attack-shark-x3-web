import { LiftOffDistanceMm, PollingRateHz } from '../protocol/x3Protocol';

export type TransportKind = 'bridge' | 'webhid' | 'mock';
export type ApplyTarget = 'all' | 'dpi' | 'polling' | 'sensor' | 'debounce' | 'power' | 'buttons' | 'mouse_attr';

export interface MouseProfileData {
  stages: number[];        // 6 stages (50..26000)
  stageColors: string[];   // 6 hex colors
  activeStage: number;     // 0..5
  pollingRate: PollingRateHz;
  lod: LiftOffDistanceMm;
  debounce: number;        // 2..20 ms (step 2)
  rippleControl: boolean;
  angleSnap: boolean;
  motionSync: boolean;
  sleepMinutes: number;
  pointerSpeed: number;    // 1..20
  doubleClickSpeed: number;// 200..900 ms
  scrollLines: number;     // 1..10
  buttons: number[];       // 5 programmable UI buttons [Left, Right, Middle, Forward, Backward]
}

export interface NamedProfile {
  id: string;
  name: string;
  storageType: 'browser' | 'onboard-active';
  updatedAt: string;
  data: MouseProfileData;
}

export interface MacroDefinition {
  id: string;
  name: string;
  events: string[];
}

export interface HidCollectionSummary {
  usagePage: string;
  usage: string;
  inputReports: number[];
  outputReports: number[];
  featureReports: number[];
}

export interface DeviceStatus {
  connected: boolean;
  transportKind: TransportKind;
  deviceName: string;
  connectionMode: string;
  vid: string | null;
  pid: string | null;
  batteryPercent: number;
  charging: boolean;
  sleeping: boolean;
  activeDpiStage: number;
  webHidSupported: boolean;
  webHidFeatureWriteBlocked?: boolean;
  collections?: HidCollectionSummary[];
}

export interface PacketResultItem {
  name: string;
  reportId: string;
  length: number;
  hex: string;
  ok: boolean;
  errorCode?: number;
  simulated?: boolean;
}

export interface DiagnosticLogEntry {
  id: string;
  timestamp: string;
  direction: 'TX' | 'RX' | 'SYS';
  transport: TransportKind;
  summary: string;
  hex?: string;
  ok: boolean;
}

export const DEFAULT_PROFILE_DATA: MouseProfileData = {
  stages: [800, 1600, 2400, 3200, 5000, 26000],
  stageColors: ['#ff0000', '#00ff00', '#0000ff', '#ffff00', '#00ffff', '#ff00ff'],
  activeStage: 1, // Stage 2 (1600 DPI)
  pollingRate: 1000,
  lod: 1,
  debounce: 8,
  rippleControl: false,
  angleSnap: false,
  motionSync: false,
  sleepMinutes: 1,
  pointerSpeed: 10,
  doubleClickSpeed: 500,
  scrollLines: 3,
  buttons: [1, 2, 3, 5, 4]
};
