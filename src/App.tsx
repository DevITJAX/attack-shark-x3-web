import React, { useEffect, useRef, useState } from 'react';
import {
  BUTTON_ACTION_OPTIONS,
  LiftOffDistanceMm,
  PollingRateHz,
  buildButtonMappingPacket,
  buildDebounceSleepPacket,
  buildDpiSensorPacket,
  buildPollingRatePacket,
  clampDpiValue,
  hasLeftClickAssigned,
  toHexString
} from './protocol/x3Protocol';
import { AttackSharkHardwareManager } from './transport/hardwareManager';
import {
  ApplyTarget,
  DEFAULT_PROFILE_DATA,
  DeviceStatus,
  DiagnosticLogEntry,
  MacroDefinition,
  MouseProfileData,
  NamedProfile,
  TransportKind
} from './transport/types';

type NavTab =
  | 'dashboard'
  | 'performance'
  | 'buttons'
  | 'profiles'
  | 'device'
  | 'diagnostics'
  | 'classic';

function dpiToVisualPercent(dpi: number): number {
  const clamped = Math.max(50, Math.min(26000, dpi));
  if (clamped <= 5000) {
    return 6 + (clamped / 5000) * 28;
  }
  return 34 + ((clamped - 5000) / 21000) * 66;
}

function visualPercentToDpi(pct: number): number {
  const p = Math.max(0, Math.min(100, pct));
  const raw = p <= 34 ? ((p - 6) / 28) * 5000 : 5000 + ((p - 34) / 66) * 21000;
  return clampDpiValue(raw);
}

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<NavTab>('classic');
  const [transportMode, setTransportMode] = useState<TransportKind>('bridge');
  const [status, setStatus] = useState<DeviceStatus>({
    connected: false,
    transportKind: 'bridge',
    deviceName: 'Attack Shark X3 (PAW3395)',
    connectionMode: 'Connecting...',
    vid: '0x1D57',
    pid: '0xFA60',
    batteryPercent: 90,
    charging: false,
    sleeping: false,
    activeDpiStage: 1,
    webHidSupported: typeof navigator !== 'undefined' && 'hid' in navigator
  });

  const [profiles, setProfiles] = useState<NamedProfile[]>(() => {
    try {
      const saved = localStorage.getItem('attackshark_x3_react_profiles_v1');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch (_) {}
    return [
      {
        id: 'prof-1',
        name: 'Profile1',
        storageType: 'onboard-active',
        updatedAt: new Date().toLocaleTimeString(),
        data: JSON.parse(JSON.stringify(DEFAULT_PROFILE_DATA))
      }
    ];
  });

  const [activeProfileIdx, setActiveProfileIdx] = useState<number>(0);
  const [macros, setMacros] = useState<MacroDefinition[]>([
    { id: 'mac-1', name: 'Macro1', events: ['KeyDown: E', 'Delay: 20ms', 'KeyUp: E'] }
  ]);
  const [activeMacroIdx, setActiveMacroIdx] = useState<number>(0);
  const [recordingMacro, setRecordingMacro] = useState<boolean>(false);
  const [showMacroModal, setShowMacroModal] = useState<boolean>(false);
  const [highlightedButton, setHighlightedButton] = useState<number | null>(null);
  const [collapsedPanels, setCollapsedPanels] = useState<Record<string, boolean>>({
    polling: true,
    mouseAttr: true,
    powerMgmt: true
  });
  const [logs, setLogs] = useState<DiagnosticLogEntry[]>([]);
  const [toast, setToast] = useState<string | null>(null);
  const seenServerEventsRef = useRef<number>(0);

  const hwRef = useRef<AttackSharkHardwareManager | null>(null);
  if (!hwRef.current) {
    hwRef.current = new AttackSharkHardwareManager((evt) => {
      addLog('RX', 'webhid', evt.summary, evt.hex, true);
    });
  }

  const currentProfileObj = profiles[activeProfileIdx] || profiles[0];
  const prof = currentProfileObj.data;

  const showToastMsg = (msg: string) => {
    setToast(msg);
  };

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 2600);
    return () => clearTimeout(t);
  }, [toast]);

  useEffect(() => {
    try {
      localStorage.setItem('attackshark_x3_react_profiles_v1', JSON.stringify(profiles));
    } catch (_) {}
  }, [profiles]);

  const addLog = (
    direction: 'TX' | 'RX' | 'SYS',
    transport: TransportKind,
    summary: string,
    hex?: string,
    ok = true
  ) => {
    setLogs((prev) => [
      {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        timestamp: new Date().toLocaleTimeString(),
        direction,
        transport,
        summary,
        hex,
        ok
      },
      ...prev.slice(0, 99)
    ]);
  };

  const refreshStatus = async () => {
    if (!hwRef.current) return;
    const st = await hwRef.current.getStatus();
    setStatus(st);

    if (st.transportKind === 'bridge' && st.connected) {
      const bridgeBase =
        typeof window !== 'undefined' &&
        window.location.port !== '3000' &&
        window.location.port !== '5173'
          ? 'http://127.0.0.1:3000'
          : '';
      try {
        const rawResp = await fetch(`${bridgeBase}/api/status`);
        const rawData = await rawResp.json();
        if (Array.isArray(rawData.events) && rawData.events.length > seenServerEventsRef.current) {
          const fresh = rawData.events.slice(seenServerEventsRef.current);
          seenServerEventsRef.current = rawData.events.length;
          fresh.forEach((ev: any) => {
            addLog('RX', 'bridge', `Input Report col03 (${ev.type})`, (ev.bytes || []).join(' '), true);
          });
        }
      } catch (_) {}
    }
  };

  useEffect(() => {
    refreshStatus();
    const timer = setInterval(refreshStatus, 2500);
    return () => clearInterval(timer);
  }, [transportMode]);

  useEffect(() => {
    if (!recordingMacro) return;
    const onKeyDown = (e: KeyboardEvent) => {
      e.preventDefault();
      setMacros((prev) =>
        prev.map((m, i) =>
          i === activeMacroIdx ? { ...m, events: [...m.events, `Key: ${e.code} (20ms)`] } : m
        )
      );
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [recordingMacro, activeMacroIdx]);

  const updateProfileData = (updater: (prev: MouseProfileData) => MouseProfileData) => {
    setProfiles((prev) =>
      prev.map((item, idx) =>
        idx === activeProfileIdx
          ? {
              ...item,
              updatedAt: new Date().toLocaleTimeString(),
              data: updater(item.data)
            }
          : item
      )
    );
  };

  const applyToHardware = async (target: ApplyTarget, customData?: MouseProfileData) => {
    if (!hwRef.current) return;
    const dataToUse = customData || prof;
    const res = await hwRef.current.applyConfiguration(target, dataToUse);
    res.results.forEach((r) => {
      addLog('TX', hwRef.current!.getTransportMode(), `${r.name} (${r.reportId}, ${r.length}B)`, r.hex, r.ok);
    });
    if (typeof res.batteryPercent === 'number') {
      setStatus((prev) => ({
        ...prev,
        batteryPercent: res.batteryPercent!,
        charging: Boolean(res.charging)
      }));
    }
    if (res.ok) {
      const modeTag = hwRef.current.getTransportMode() === 'mock' ? ' [SIMULATED]' : '';
      showToastMsg(`Applied (${target.toUpperCase()})${modeTag}`);
    } else {
      showToastMsg(res.errorMessage || 'Hardware write failed');
    }
  };

  const handleQueryBattery = async () => {
    if (!hwRef.current) return;
    const res = await hwRef.current.queryBattery();
    addLog('TX', hwRef.current.getTransportMode(), 'Report 0x0C Status/Battery Query', res.hex, res.ok);
    if (res.ok) {
      setStatus((prev) => ({
        ...prev,
        batteryPercent: res.batteryPercent,
        charging: res.charging
      }));
      showToastMsg(`Battery: ${res.batteryPercent}%${res.charging ? ' (Charging)' : ''}`);
    }
  };

  const handleSwitchTransport = async (nextMode: TransportKind) => {
    if (!hwRef.current) return;
    if (nextMode === 'webhid') {
      const res = await hwRef.current.connectWebHid();
      setTransportMode(hwRef.current.getTransportMode());
      setStatus(res.status);
      addLog('SYS', 'webhid', res.message, undefined, res.ok);
      showToastMsg(res.message);
      return;
    }
    hwRef.current.setTransportMode(nextMode);
    setTransportMode(nextMode);
    const st = await hwRef.current.getStatus();
    setStatus(st);
    addLog('SYS', nextMode, `Switched transport mode to ${nextMode.toUpperCase()}`, undefined, true);
    showToastMsg(`Transport: ${nextMode.toUpperCase()}`);
  };

  const handleButtonChange = (btnIdx: number, nextActionId: number) => {
    const nextButtons = [...prof.buttons];
    nextButtons[btnIdx] = nextActionId;
    if (!hasLeftClickAssigned(nextButtons)) {
      showToastMsg('Safety Lock: At least one button must remain assigned to Left Click!');
      return;
    }
    const nextData = { ...prof, buttons: nextButtons };
    updateProfileData(() => nextData);
    applyToHardware('buttons', nextData);
  };

  const handleResetDefaults = () => {
    const fresh = JSON.parse(JSON.stringify(DEFAULT_PROFILE_DATA)) as MouseProfileData;
    updateProfileData(() => fresh);
    applyToHardware('all', fresh);
    showToastMsg('Restored verified factory defaults');
  };

  const toggleCollapse = (key: string) => {
    setCollapsedPanels((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const exportDiagnosticReport = () => {
    const report = {
      generatedAt: new Date().toISOString(),
      browserUserAgent: navigator.userAgent,
      webHidAvailable: status.webHidSupported,
      transportMode: status.transportKind,
      deviceStatus: {
        connected: status.connected,
        deviceName: status.deviceName,
        connectionMode: status.connectionMode,
        vid: status.vid,
        pid: status.pid,
        batteryPercent: status.batteryPercent,
        charging: status.charging,
        webHidFeatureWriteBlocked: status.webHidFeatureWriteBlocked,
        collections: status.collections
      },
      activeProfile: prof,
      recentLogs: logs.slice(0, 40)
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'attackshark-x3-diagnostics.json';
    a.click();
  };

  // Interactive Mouse Diagram SVG Component used across Classic, Dashboard, and Button Mapping views
  const renderMouseSvg = () => {
    const ledColors = ['#ff2020', '#00d8ff', '#28ff50', '#ffe600', '#00ffff', '#ff00ff'];
    const ledColor = prof.stageColors?.[prof.activeStage] || ledColors[prof.activeStage] || '#00d8ff';
    return (
      <svg className="mouse-svg" viewBox="0 0 320 560" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <radialGradient id="mouseBodyGrad" cx="50%" cy="38%" r="60%" fx="45%" fy="30%">
            <stop offset="0%" stopColor="#ffffff" />
            <stop offset="65%" stopColor="#f2f2f2" />
            <stop offset="92%" stopColor="#d9d9d9" />
            <stop offset="100%" stopColor="#bcbcbc" />
          </radialGradient>
          <linearGradient id="buttonShellGrad" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#eaeaea" />
            <stop offset="40%" stopColor="#ffffff" />
            <stop offset="100%" stopColor="#efefef" />
          </linearGradient>
          <linearGradient id="wheelGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#181818" />
            <stop offset="22%" stopColor="#3a3a3a" />
            <stop offset="50%" stopColor="#141414" />
            <stop offset="78%" stopColor="#3a3a3a" />
            <stop offset="100%" stopColor="#181818" />
          </linearGradient>
          <filter id="mouseShadow" x="-15%" y="-10%" width="130%" height="125%">
            <feDropShadow dx="0" dy="14" stdDeviation="14" floodColor="#000000" floodOpacity="0.65" />
          </filter>
        </defs>

        {/* Side Thumb Buttons (4 = Front, 5 = Rear) */}
        <path
          d="M59 225 C54 227, 53 235, 53 252 C53 268, 54 276, 59 278 L65 278 L65 225 Z"
          fill="#e8e8e8"
          stroke="#999"
          strokeWidth="1.2"
        />
        <path
          d="M59 283 C54 285, 53 295, 54 314 C55 328, 57 336, 61 338 L67 338 L67 283 Z"
          fill="#e4e4e4"
          stroke="#999"
          strokeWidth="1.2"
        />

        {/* Main Outer Shell Silhouette */}
        <path
          d="M160 46 C218 46, 252 76, 256 138 C259 186, 252 232, 249 278 C246 322, 260 374, 257 426 C253 488, 216 526, 160 526 C104 526, 67 488, 63 426 C60 374, 74 322, 71 278 C68 232, 61 186, 64 138 C68 76, 102 46, 160 46 Z"
          fill="url(#mouseBodyGrad)"
          stroke="#b5b5b5"
          strokeWidth="1.5"
          filter="url(#mouseShadow)"
        />

        {/* Left & Right Click Seams */}
        <path
          d="M64 146 L64 238 C64 256, 73 266, 94 268 L146 272 L146 95 L160 95 L160 46"
          fill="url(#buttonShellGrad)"
          stroke="#333333"
          strokeWidth="1.6"
        />
        <path
          d="M256 146 L256 238 C256 256, 247 266, 226 268 L174 272 L174 95 L160 95 L160 46"
          fill="url(#buttonShellGrad)"
          stroke="#333333"
          strokeWidth="1.6"
        />

        {/* Center Scroll Wheel Island */}
        <rect x="144" y="94" width="32" height="178" rx="16" fill="#f7f7f7" stroke="#444444" strokeWidth="1.5" />
        <rect x="148" y="103" width="24" height="78" rx="9" fill="#1a1a1a" stroke="#555555" strokeWidth="1" />
        <rect x="150" y="107" width="20" height="70" rx="6" fill="url(#wheelGrad)" stroke="#d0d0d0" strokeWidth="1" />
        <g stroke="#2a2a2a" strokeWidth="2">
          <line x1="152" y1="115" x2="168" y2="115" />
          <line x1="152" y1="122" x2="168" y2="122" />
          <line x1="152" y1="129" x2="168" y2="129" />
          <line x1="152" y1="136" x2="168" y2="136" />
          <line x1="152" y1="143" x2="168" y2="143" />
          <line x1="152" y1="150" x2="168" y2="150" />
          <line x1="152" y1="157" x2="168" y2="157" />
          <line x1="152" y1="164" x2="168" y2="164" />
          <line x1="152" y1="171" x2="168" y2="171" />
        </g>

        {/* DPI Stage LED Indicator */}
        <rect x="157.5" y="236" width="5" height="16" rx="2.5" fill={ledColor} />

        {/* Red Callout Circles 1..5 */}
        {[
          { idx: 0, num: 1, cx: 114, cy: 146 },
          { idx: 2, num: 3, cx: 160, cy: 146 },
          { idx: 1, num: 2, cx: 206, cy: 146 },
          { idx: 3, num: 4, cx: 56, cy: 242 },
          { idx: 4, num: 5, cx: 56, cy: 306 }
        ].map((b) => (
          <g
            key={b.num}
            className="mouse-callout"
            onClick={() => {
              setHighlightedButton(b.idx);
              setTimeout(() => setHighlightedButton(null), 1500);
            }}
          >
            <circle
              cx={b.cx}
              cy={b.cy}
              r="14"
              fill={highlightedButton === b.idx ? '#ff3b3b' : '#e61010'}
              stroke={highlightedButton === b.idx ? '#ffffff' : 'none'}
              strokeWidth="2"
            />
            <text x={b.cx} y={b.cy + 5} textAnchor="middle" fill="#ffffff" fontSize="14" fontWeight="700">
              {b.num}
            </text>
          </g>
        ))}
      </svg>
    );
  };

  // Vertical DPI Sliders Card Component (Exact match to Attack Shark X3 desktop app)
  const renderVerticalDpiCard = () => (
    <div className="dpi-card">
      <div className="dpi-columns">
        {prof.stages.map((dpiVal, idx) => {
          const pct = dpiToVisualPercent(dpiVal);
          return (
            <div className="dpi-col" key={idx}>
              <div
                className="dpi-vtrack-wrap"
                title={`Drag to adjust Stage ${idx + 1} DPI (50 - 26000)`}
                onMouseDown={(e) => {
                  e.preventDefault();
                  const wrap = e.currentTarget;
                  const updateFromY = (clientY: number) => {
                    const rect = wrap.getBoundingClientRect();
                    const rel = 1 - (clientY - rect.top) / rect.height;
                    const nextDpi = visualPercentToDpi(rel * 100);
                    updateProfileData((prev) => {
                      const nextStages = [...prev.stages];
                      nextStages[idx] = nextDpi;
                      return { ...prev, stages: nextStages };
                    });
                  };
                  updateFromY(e.clientY);
                  const onMove = (ev: MouseEvent) => updateFromY(ev.clientY);
                  const onUp = () => {
                    window.removeEventListener('mousemove', onMove);
                    window.removeEventListener('mouseup', onUp);
                  };
                  window.addEventListener('mousemove', onMove);
                  window.addEventListener('mouseup', onUp);
                }}
              >
                <div className="dpi-vtrack">
                  <div className="dpi-vfill" style={{ height: `${pct}%` }} />
                  <div className="dpi-vthumb" style={{ bottom: `${pct}%` }} />
                </div>
              </div>
              <div className="dpi-step-label">50</div>
              <input
                type="text"
                className="dpi-val-input"
                value={dpiVal}
                onChange={(e) => {
                  const raw = parseInt(e.target.value, 10);
                  if (!Number.isNaN(raw)) {
                    updateProfileData((prev) => {
                      const nextStages = [...prev.stages];
                      nextStages[idx] = Math.max(1, Math.min(26000, raw));
                      return { ...prev, stages: nextStages };
                    });
                  }
                }}
                onBlur={() => {
                  updateProfileData((prev) => {
                    const nextStages = [...prev.stages];
                    nextStages[idx] = clampDpiValue(nextStages[idx]);
                    return { ...prev, stages: nextStages };
                  });
                }}
              />
              <button
                type="button"
                className={`dpi-stage-dot ${prof.activeStage === idx ? 'active' : ''}`}
                title={`Activate Stage ${idx + 1} (${dpiVal} DPI)`}
                onClick={() => {
                  const nextData = { ...prof, activeStage: idx };
                  updateProfileData(() => nextData);
                  applyToHardware('dpi', nextData);
                }}
              />
            </div>
          );
        })}
      </div>
      <div className="dpi-apply-row">
        <button className="dpi-apply-btn" type="button" onClick={() => applyToHardware('dpi')}>
          Apply
        </button>
      </div>
    </div>
  );

  // Button Settings List Component (Buttons 1..5)
  const renderButtonSettingsList = () => (
    <div className="x3-panel-body buttons-list">
      {[0, 1, 2, 3, 4].map((btnIdx) => (
        <div
          key={btnIdx}
          className={`btn-row ${highlightedButton === btnIdx ? 'highlight' : ''}`}
        >
          <span className="btn-num">{btnIdx + 1}</span>
          <select
            className="btn-select"
            value={prof.buttons[btnIdx]}
            onChange={(e) => handleButtonChange(btnIdx, parseInt(e.target.value, 10))}
          >
            {BUTTON_ACTION_OPTIONS.map((opt) => (
              <option key={opt.id} value={opt.id}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
      ))}
    </div>
  );

  return (
    <div className="x3-window">
      {/* Top Header Bar */}
      <header className="x3-header">
        <div className="header-left">
          <div className="conn-badge" title="Active Hardware Transport Status">
            <span className={`conn-dot ${status.connected ? 'online' : 'offline'}`} />
            <span>
              {status.connected ? status.connectionMode : 'Disconnected'}
              {status.transportKind === 'mock' ? ' (Mock Mode)' : ''}
            </span>
          </div>
          <select
            className="transport-select"
            value={transportMode}
            onChange={(e) => handleSwitchTransport(e.target.value as TransportKind)}
            title="Select Hardware Communication Layer"
          >
            <option value="bridge">Transport: Native Bridge (Verified)</option>
            <option value="webhid">Transport: Browser WebHID</option>
            <option value="mock">Transport: Mock Simulator</option>
          </select>
        </div>

        <div className="brand-logo">
          <svg className="shark-svg" viewBox="0 0 320 68" xmlns="http://www.w3.org/2000/svg">
            <path
              d="M44 8 C28 18, 16 38, 12 60 L25 60 C28 45, 34 33, 43 24 C41 37, 42 49, 46 60 L60 60 C55 44, 53 25, 58 8 Z"
              fill="#ffffff"
            />
            <path d="M24 44 Q36 39 49 45" stroke="#232323" strokeWidth="3" fill="none" />
            <text
              x="68"
              y="42"
              fill="#ffffff"
              fontFamily="'Segoe UI', Arial, sans-serif"
              fontWeight="900"
              fontStyle="italic"
              fontSize="23"
              letterSpacing="1.5"
            >
              ATTACK SHARK
            </text>
            <polyline
              points="69,53 74,49 79,53 84,49 89,53 94,49 99,53 104,49 109,53 114,49 119,53"
              fill="none"
              stroke="#ffffff"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>

        <div className="header-right">
          <button
            className={`icon-btn wireless-icon ${status.connected ? 'online' : ''}`}
            onClick={handleQueryBattery}
            title="Query Live Battery & Status (Report 0x0C)"
          >
            <svg
              viewBox="0 0 28 24"
              width="22"
              height="19"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
            >
              <circle cx="14" cy="12" r="2.2" fill="currentColor" stroke="none" />
              <path d="M9.5 8.5 A6 6 0 0 0 9.5 15.5" />
              <path d="M18.5 8.5 A6 6 0 0 1 18.5 15.5" />
              <path d="M6.5 5.5 A10 10 0 0 0 6.5 18.5" />
              <path d="M21.5 5.5 A10 10 0 0 1 21.5 18.5" />
              <path d="M3.5 2.5 A14 14 0 0 0 3.5 21.5" />
              <path d="M24.5 2.5 A14 14 0 0 1 24.5 21.5" />
            </svg>
          </button>
          <button
            className="top-action-btn primary"
            onClick={() => applyToHardware('all')}
            title="Write all active settings to Attack Shark X3 onboard memory"
          >
            Sync Hardware
          </button>
        </div>
      </header>

      {/* Navigation Sub-Bar (Switches between Classic Native X3 Layout and Modern Enthusiast Views) */}
      <nav className="x3-subnav">
        {[
          { id: 'classic', label: 'Classic X3 App View' },
          { id: 'dashboard', label: 'Dashboard' },
          { id: 'performance', label: 'Performance & Sensor' },
          { id: 'buttons', label: 'Button Mapping' },
          { id: 'profiles', label: 'Profiles' },
          { id: 'device', label: 'Device Info & Matrix' },
          { id: 'diagnostics', label: `Diagnostics (${logs.length})` }
        ].map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={`subnav-tab ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id as NavTab)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {/* VIEW 1: CLASSIC X3 NATIVE DESKTOP REPLICA (3-Column Layout from User Screenshot) */}
      {activeTab === 'classic' && (
        <main className="x3-main">
          {/* LEFT COLUMN */}
          <section className="col-left">
            <div className={`x3-panel ${collapsedPanels.buttons ? 'collapsed' : ''}`}>
              <div className="x3-panel-header" onClick={() => toggleCollapse('buttons')}>
                <span>Button Settings</span>
                <button className="collapse-btn" type="button">
                  −
                </button>
              </div>
              {renderButtonSettingsList()}
            </div>

            <button
              className="macro-manager-btn"
              type="button"
              onClick={() => setShowMacroModal(true)}
            >
              Macro Manager
            </button>

            <div className={`x3-panel ${collapsedPanels.profile ? 'collapsed' : ''}`}>
              <div className="x3-panel-header" onClick={() => toggleCollapse('profile')}>
                <span>Profile</span>
                <button className="collapse-btn" type="button">
                  −
                </button>
              </div>
              <div className="x3-panel-body profile-body">
                <div className="profile-listbox">
                  {profiles.map((p, idx) => (
                    <div
                      key={p.id}
                      className={`profile-item ${idx === activeProfileIdx ? 'active' : ''}`}
                      onClick={() => {
                        setActiveProfileIdx(idx);
                        applyToHardware('all', p.data);
                      }}
                    >
                      {p.name}
                    </div>
                  ))}
                </div>
                <div className="profile-toolbar">
                  <button
                    className="prof-tool-btn"
                    title="New Profile"
                    type="button"
                    onClick={() => {
                      const nextNum = profiles.length + 1;
                      const created: NamedProfile = {
                        id: `prof-${Date.now()}`,
                        name: `Profile${nextNum}`,
                        storageType: 'browser',
                        updatedAt: new Date().toLocaleTimeString(),
                        data: JSON.parse(JSON.stringify(DEFAULT_PROFILE_DATA))
                      };
                      setProfiles((prev) => [...prev, created]);
                      setActiveProfileIdx(profiles.length);
                    }}
                  >
                    +
                  </button>
                  <button
                    className="prof-tool-btn"
                    title="Delete Profile"
                    type="button"
                    onClick={() => {
                      if (profiles.length <= 1) {
                        showToastMsg('Cannot delete the last profile');
                        return;
                      }
                      setProfiles((prev) => prev.filter((_, i) => i !== activeProfileIdx));
                      setActiveProfileIdx(Math.max(0, activeProfileIdx - 1));
                    }}
                  >
                    🗑
                  </button>
                  <button
                    className="prof-tool-btn"
                    title="Rename Profile"
                    type="button"
                    onClick={() => {
                      const name = prompt('Rename Profile:', currentProfileObj.name);
                      if (name && name.trim()) {
                        setProfiles((prev) =>
                          prev.map((p, i) => (i === activeProfileIdx ? { ...p, name: name.trim() } : p))
                        );
                      }
                    }}
                  >
                    ✎
                  </button>
                  <button
                    className="prof-tool-btn"
                    title="Export Profile JSON"
                    type="button"
                    onClick={() => {
                      const blob = new Blob([JSON.stringify(currentProfileObj, null, 2)], {
                        type: 'application/json'
                      });
                      const a = document.createElement('a');
                      a.href = URL.createObjectURL(blob);
                      a.download = `${currentProfileObj.name}.json`;
                      a.click();
                    }}
                  >
                    📤
                  </button>
                  <label className="prof-tool-btn" title="Import Profile JSON">
                    📥
                    <input
                      type="file"
                      accept=".json"
                      style={{ display: 'none' }}
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        if (!file) return;
                        const reader = new FileReader();
                        reader.onload = () => {
                          try {
                            const parsed = JSON.parse(String(reader.result));
                            if (parsed && parsed.data) {
                              setProfiles((prev) => [...prev, parsed]);
                              setActiveProfileIdx(profiles.length);
                              applyToHardware('all', parsed.data);
                            }
                          } catch (_) {
                            showToastMsg('Invalid profile JSON');
                          }
                        };
                        reader.readAsText(file);
                      }}
                    />
                  </label>
                  <button
                    className="prof-tool-btn"
                    title="Reset to Factory Defaults"
                    type="button"
                    onClick={handleResetDefaults}
                  >
                    ↻
                  </button>
                </div>
              </div>
            </div>

            <div className={`x3-panel ${collapsedPanels.power ? 'collapsed' : ''}`}>
              <div className="x3-panel-header" onClick={() => toggleCollapse('power')}>
                <span>Power</span>
                <button className="collapse-btn" type="button">
                  −
                </button>
              </div>
              <div
                className="x3-panel-body power-body"
                onClick={handleQueryBattery}
                title="Click to query live battery from mouse hardware (0x0C)"
              >
                <div className="battery-graphic">
                  <div className="battery-shell">
                    <div
                      className="battery-fill"
                      style={{ width: `${Math.max(5, Math.min(100, status.batteryPercent))}%` }}
                    />
                  </div>
                  <div className="battery-cap" />
                </div>
                <div className="battery-percent">
                  {status.batteryPercent}%{status.charging ? ' ⚡' : ''}
                </div>
              </div>
            </div>
          </section>

          {/* CENTER COLUMN */}
          <section className="col-center">
            <div className="mouse-stage">{renderMouseSvg()}</div>
          </section>

          {/* RIGHT COLUMN */}
          <section className="col-right">
            {renderVerticalDpiCard()}

            {/* Polling Rate Settings */}
            <div className={`x3-panel ${collapsedPanels.polling ? 'collapsed' : ''}`}>
              <div className="x3-panel-header" onClick={() => toggleCollapse('polling')}>
                <span>Polling Rate Settings</span>
                <button className="collapse-btn" type="button">
                  −
                </button>
              </div>
              <div className="x3-panel-body radio-grid-4">
                {([125, 250, 500, 1000] as PollingRateHz[]).map((hz) => (
                  <label className="x3-radio" key={hz}>
                    <input
                      type="radio"
                      name="pollingRate"
                      checked={prof.pollingRate === hz}
                      onChange={() => {
                        const nextData = { ...prof, pollingRate: hz };
                        updateProfileData(() => nextData);
                        applyToHardware('polling', nextData);
                      }}
                    />
                    <span className="radio-dot" />
                    <span>{hz}Hz</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Mouse Attribute */}
            <div className={`x3-panel ${collapsedPanels.mouseAttr ? 'collapsed' : ''}`}>
              <div className="x3-panel-header" onClick={() => toggleCollapse('mouseAttr')}>
                <span>Mouse Attribute</span>
                <button className="collapse-btn" type="button">
                  −
                </button>
              </div>
              <div className="x3-panel-body attr-body">
                <div className="attr-row">
                  <div className="attr-label">
                    <span>Moving Speed</span>
                    <span>{prof.pointerSpeed}</span>
                  </div>
                  <input
                    type="range"
                    className="x3-hslider"
                    min={1}
                    max={20}
                    value={prof.pointerSpeed}
                    onChange={(e) => {
                      const nextData = { ...prof, pointerSpeed: parseInt(e.target.value, 10) };
                      updateProfileData(() => nextData);
                    }}
                    onMouseUp={() => applyToHardware('mouse_attr')}
                  />
                </div>
                <div className="attr-row">
                  <div className="attr-label">
                    <span>Double Click Speed</span>
                    <span>{prof.doubleClickSpeed} ms</span>
                  </div>
                  <input
                    type="range"
                    className="x3-hslider"
                    min={200}
                    max={900}
                    step={50}
                    value={prof.doubleClickSpeed}
                    onChange={(e) => {
                      const nextData = { ...prof, doubleClickSpeed: parseInt(e.target.value, 10) };
                      updateProfileData(() => nextData);
                    }}
                    onMouseUp={() => applyToHardware('mouse_attr')}
                  />
                </div>
                <div className="attr-row">
                  <div className="attr-label">
                    <span>Rolling Speed</span>
                    <span>{prof.scrollLines}</span>
                  </div>
                  <input
                    type="range"
                    className="x3-hslider"
                    min={1}
                    max={10}
                    value={prof.scrollLines}
                    onChange={(e) => {
                      const nextData = { ...prof, scrollLines: parseInt(e.target.value, 10) };
                      updateProfileData(() => nextData);
                    }}
                    onMouseUp={() => applyToHardware('mouse_attr')}
                  />
                </div>
              </div>
            </div>

            {/* Power Management */}
            <div className={`x3-panel ${collapsedPanels.powerMgmt ? 'collapsed' : ''}`}>
              <div className="x3-panel-header" onClick={() => toggleCollapse('powerMgmt')}>
                <span>Power Management</span>
                <button className="collapse-btn" type="button">
                  −
                </button>
              </div>
              <div className="x3-panel-body attr-body">
                <div className="attr-row">
                  <div className="attr-label">
                    <span>Sleep Timer</span>
                    <span>{prof.sleepMinutes} Min</span>
                  </div>
                  <select
                    className="btn-select full-width"
                    value={prof.sleepMinutes}
                    onChange={(e) => {
                      const nextData = { ...prof, sleepMinutes: parseInt(e.target.value, 10) };
                      updateProfileData(() => nextData);
                      applyToHardware('power', nextData);
                    }}
                  >
                    {[1, 3, 5, 10, 15, 30].map((m) => (
                      <option key={m} value={m}>
                        {m} Minute{m > 1 ? 's' : ''}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            {/* Lift Of Distance */}
            <div className={`x3-panel ${collapsedPanels.lod ? 'collapsed' : ''}`}>
              <div className="x3-panel-header" onClick={() => toggleCollapse('lod')}>
                <span>Lift Of Distance</span>
                <button className="collapse-btn" type="button">
                  −
                </button>
              </div>
              <div className="x3-panel-body radio-pair">
                {([1, 2] as LiftOffDistanceMm[]).map((mm) => (
                  <label className="x3-radio" key={mm}>
                    <input
                      type="radio"
                      name="lod"
                      checked={prof.lod === mm}
                      onChange={() => {
                        const nextData = { ...prof, lod: mm };
                        updateProfileData(() => nextData);
                        applyToHardware('sensor', nextData);
                      }}
                    />
                    <span className="radio-dot" />
                    <span>{mm} MM</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Key Response Time */}
            <div className={`x3-panel ${collapsedPanels.debounce ? 'collapsed' : ''}`}>
              <div className="x3-panel-header" onClick={() => toggleCollapse('debounce')}>
                <span>Key Response Time</span>
                <button className="collapse-btn" type="button">
                  −
                </button>
              </div>
              <div className="x3-panel-body debounce-body">
                <div className="debounce-slider-wrap">
                  <input
                    type="range"
                    className="x3-hslider"
                    min={2}
                    max={20}
                    step={2}
                    value={prof.debounce}
                    style={{
                      background: `linear-gradient(90deg, #ff0c0c ${
                        ((prof.debounce - 2) / 18) * 100
                      }%, #484848 ${((prof.debounce - 2) / 18) * 100}%)`
                    }}
                    onChange={(e) => {
                      const nextData = { ...prof, debounce: parseInt(e.target.value, 10) };
                      updateProfileData(() => nextData);
                    }}
                    onMouseUp={() => applyToHardware('debounce')}
                  />
                </div>
                <div className="debounce-value-box">{prof.debounce} MS</div>
              </div>
            </div>

            {/* Ripple Control */}
            <div className={`x3-panel ${collapsedPanels.ripple ? 'collapsed' : ''}`}>
              <div className="x3-panel-header" onClick={() => toggleCollapse('ripple')}>
                <span>Ripple Control</span>
                <button className="collapse-btn" type="button">
                  −
                </button>
              </div>
              <div className="x3-panel-body radio-pair">
                {[false, true].map((val) => (
                  <label className="x3-radio" key={String(val)}>
                    <input
                      type="radio"
                      name="rippleControl"
                      checked={prof.rippleControl === val}
                      onChange={() => {
                        const nextData = { ...prof, rippleControl: val };
                        updateProfileData(() => nextData);
                        applyToHardware('sensor', nextData);
                      }}
                    />
                    <span className="radio-dot" />
                    <span>{val ? 'On' : 'Off'}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Angle Snap */}
            <div className={`x3-panel ${collapsedPanels.angle ? 'collapsed' : ''}`}>
              <div className="x3-panel-header" onClick={() => toggleCollapse('angle')}>
                <span>Angle Snap</span>
                <button className="collapse-btn" type="button">
                  −
                </button>
              </div>
              <div className="x3-panel-body radio-pair">
                {[false, true].map((val) => (
                  <label className="x3-radio" key={String(val)}>
                    <input
                      type="radio"
                      name="angleSnap"
                      checked={prof.angleSnap === val}
                      onChange={() => {
                        const nextData = { ...prof, angleSnap: val };
                        updateProfileData(() => nextData);
                        applyToHardware('sensor', nextData);
                      }}
                    />
                    <span className="radio-dot" />
                    <span>{val ? 'On' : 'Off'}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Motion Sync */}
            <div className={`x3-panel ${collapsedPanels.motion ? 'collapsed' : ''}`}>
              <div className="x3-panel-header" onClick={() => toggleCollapse('motion')}>
                <span>Motion Sync</span>
                <button className="collapse-btn" type="button">
                  −
                </button>
              </div>
              <div className="x3-panel-body radio-pair">
                {[false, true].map((val) => (
                  <label className="x3-radio" key={String(val)}>
                    <input
                      type="radio"
                      name="motionSync"
                      checked={prof.motionSync === val}
                      onChange={() => {
                        const nextData = { ...prof, motionSync: val };
                        updateProfileData(() => nextData);
                        applyToHardware('sensor', nextData);
                      }}
                    />
                    <span className="radio-dot" />
                    <span>{val ? 'On' : 'Off'}</span>
                  </label>
                ))}
              </div>
            </div>
          </section>
        </main>
      )}

      {/* VIEW 2: DASHBOARD OVERVIEW */}
      {activeTab === 'dashboard' && (
        <main className="tab-content-grid">
          <div className="dash-card center-mouse-card">{renderMouseSvg()}</div>
          <div className="dash-col">
            <div className="dash-card">
              <h3>Hardware Telemetry &amp; Active Status</h3>
              <div className="kpi-grid">
                <div className="kpi-box">
                  <span className="kpi-label">Active DPI</span>
                  <span className="kpi-val">{prof.stages[prof.activeStage]} DPI</span>
                  <span className="kpi-sub">Stage {prof.activeStage + 1} of 6</span>
                </div>
                <div className="kpi-box">
                  <span className="kpi-label">Polling Rate</span>
                  <span className="kpi-val">{prof.pollingRate} Hz</span>
                  <span className="kpi-sub">{(1000 / prof.pollingRate).toFixed(2)} ms interval</span>
                </div>
                <div className="kpi-box">
                  <span className="kpi-label">Battery Level</span>
                  <span className="kpi-val">{status.batteryPercent}%</span>
                  <span className="kpi-sub">{status.charging ? 'Charging' : 'Discharging (0x4010)'}</span>
                </div>
                <div className="kpi-box">
                  <span className="kpi-label">Key Response</span>
                  <span className="kpi-val">{prof.debounce} ms</span>
                  <span className="kpi-sub">LOD: {prof.lod} mm</span>
                </div>
              </div>
            </div>

            <div className="dash-card">
              <h3>Quick Stage &amp; Polling Switcher</h3>
              <div className="quick-row">
                {prof.stages.map((d, idx) => (
                  <button
                    key={idx}
                    type="button"
                    className={`stage-pill-btn ${prof.activeStage === idx ? 'active' : ''}`}
                    onClick={() => {
                      const nextData = { ...prof, activeStage: idx };
                      updateProfileData(() => nextData);
                      applyToHardware('dpi', nextData);
                    }}
                  >
                    S{idx + 1}: {d}
                  </button>
                ))}
              </div>
              <div className="quick-row" style={{ marginTop: 10 }}>
                {([125, 250, 500, 1000] as PollingRateHz[]).map((hz) => (
                  <button
                    key={hz}
                    type="button"
                    className={`stage-pill-btn ${prof.pollingRate === hz ? 'active' : ''}`}
                    onClick={() => {
                      const nextData = { ...prof, pollingRate: hz };
                      updateProfileData(() => nextData);
                      applyToHardware('polling', nextData);
                    }}
                  >
                    {hz} Hz
                  </button>
                ))}
              </div>
            </div>
          </div>
        </main>
      )}

      {/* VIEW 3: PERFORMANCE & SENSOR */}
      {activeTab === 'performance' && (
        <main className="tab-content-grid">
          <div className="dash-col">
            <div className="dash-card">
              <h3>6-Stage PAW3395 DPI Configuration (50 – 26,000 DPI)</h3>
              {renderVerticalDpiCard()}
            </div>
            <div className="dash-card">
              <h3>Live Encoded Packet Preview (Report 0x04 — 56 Bytes)</h3>
              <code className="hex-preview">
                {toHexString(
                  buildDpiSensorPacket({
                    activeStage: prof.activeStage,
                    stages: prof.stages,
                    stageColors: prof.stageColors,
                    lod: prof.lod,
                    motionSync: prof.motionSync,
                    rippleControl: prof.rippleControl,
                    angleSnap: prof.angleSnap
                  })
                )}
              </code>
            </div>
          </div>
          <div className="dash-col">
            <div className="dash-card">
              <h3>Sensor &amp; Debounce Controls</h3>
              <div className="QuickSensorGrid">
                <div className="attr-row">
                  <div className="attr-label">
                    <span>Key Response Time (Debounce: 2–20 ms)</span>
                    <strong>{prof.debounce} ms</strong>
                  </div>
                  <input
                    type="range"
                    className="x3-hslider"
                    min={2}
                    max={20}
                    step={2}
                    value={prof.debounce}
                    onChange={(e) =>
                      updateProfileData((p) => ({ ...p, debounce: parseInt(e.target.value, 10) }))
                    }
                    onMouseUp={() => applyToHardware('debounce')}
                  />
                </div>
                <div className="radio-pair">
                  <span>Lift-Off Distance:</span>
                  <div>
                    {([1, 2] as LiftOffDistanceMm[]).map((mm) => (
                      <label className="x3-radio" key={mm} style={{ marginRight: 16 }}>
                        <input
                          type="radio"
                          checked={prof.lod === mm}
                          onChange={() => {
                            const next = { ...prof, lod: mm };
                            updateProfileData(() => next);
                            applyToHardware('sensor', next);
                          }}
                        />
                        <span className="radio-dot" />
                        <span>{mm} mm</span>
                      </label>
                    ))}
                  </div>
                </div>
              </div>
              <div style={{ marginTop: 12 }}>
                <div className="macro-subtitle">Report 0x05 (15 Bytes)</div>
                <code className="hex-preview">
                  {toHexString(buildDebounceSleepPacket(prof.debounce, prof.sleepMinutes))}
                </code>
              </div>
            </div>
          </div>
        </main>
      )}

      {/* VIEW 4: BUTTON MAPPING */}
      {activeTab === 'buttons' && (
        <main className="tab-content-grid">
          <div className="dash-card center-mouse-card">{renderMouseSvg()}</div>
          <div className="dash-col">
            <div className="dash-card">
              <h3>5-Button Hardware Assignment (With Left-Click Safety Lock)</h3>
              {renderButtonSettingsList()}
              <div style={{ marginTop: 12, display: 'flex', gap: 10 }}>
                <button className="dpi-apply-btn" type="button" onClick={handleResetDefaults}>
                  Reset Safe Default Mapping
                </button>
                <button
                  className="dpi-apply-btn"
                  type="button"
                  onClick={() => setShowMacroModal(true)}
                >
                  Open Macro Manager
                </button>
              </div>
            </div>
            <div className="dash-card">
              <h3>Live 18-Slot Firmware Packet Preview (Report 0x08 — 59 Bytes)</h3>
              <code className="hex-preview">
                {toHexString(buildButtonMappingPacket([...prof.buttons, 6]))}
              </code>
            </div>
          </div>
        </main>
      )}

      {/* VIEW 5: PROFILES */}
      {activeTab === 'profiles' && (
        <main className="tab-single-col">
          <div className="dash-card">
            <h3>Profile Management (Browser Storage vs. Onboard Flash Memory)</h3>
            <p className="muted-note">
              Attack Shark X3 stores one active configuration in onboard flash memory (survives unplugging and moving to another PC). Named profiles below are stored in browser localStorage and written to the mouse's onboard flash when activated.
            </p>
            <div className="profile-listbox" style={{ height: 220, marginTop: 12 }}>
              {profiles.map((p, idx) => (
                <div
                  key={p.id}
                  className={`profile-item ${idx === activeProfileIdx ? 'active' : ''}`}
                  onClick={() => {
                    setActiveProfileIdx(idx);
                    applyToHardware('all', p.data);
                  }}
                >
                  <strong>{p.name}</strong> —{' '}
                  {idx === activeProfileIdx ? '[ACTIVE IN ONBOARD FLASH]' : '[Browser Saved]'} (Updated{' '}
                  {p.updatedAt})
                </div>
              ))}
            </div>
          </div>
        </main>
      )}

      {/* VIEW 6: DEVICE INFORMATION & FEATURE SUPPORT MATRIX */}
      {activeTab === 'device' && (
        <main className="tab-single-col">
          <div className="dash-card">
            <h3>Hardware Identity &amp; Feature Support Matrix</h3>
            <table className="matrix-table">
              <thead>
                <tr>
                  <th>Feature / Capability</th>
                  <th>Status</th>
                  <th>HID Report / Mechanism</th>
                  <th>Persistence</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>6-Stage DPI &amp; Active Stage (50–26,000)</td>
                  <td className="badge-ok">Verified Hardware</td>
                  <td>Feature Report 0x04 (56 B) on col04</td>
                  <td>Onboard Flash</td>
                </tr>
                <tr>
                  <td>Polling Rate (125 / 250 / 500 / 1000 Hz)</td>
                  <td className="badge-ok">Verified Hardware</td>
                  <td>Feature Report 0x06 (9 B) on col04</td>
                  <td>Onboard Flash</td>
                </tr>
                <tr>
                  <td>5-Button Mapping (18-Slot Table)</td>
                  <td className="badge-ok">Verified Hardware</td>
                  <td>Feature Report 0x08 (59 B) on col04</td>
                  <td>Onboard Flash</td>
                </tr>
                <tr>
                  <td>LOD (1/2mm), Motion Sync, Angle Snap, Ripple</td>
                  <td className="badge-ok">Verified Hardware</td>
                  <td>Feature Report 0x04 (pkt[3..7])</td>
                  <td>Onboard Flash</td>
                </tr>
                <tr>
                  <td>Key Response Time (Debounce 2–20ms) &amp; Sleep</td>
                  <td className="badge-ok">Verified Hardware</td>
                  <td>Feature Report 0x05 (15 B, pkt[9..10])</td>
                  <td>Onboard Flash</td>
                </tr>
                <tr>
                  <td>Live Battery % &amp; Charging Telemetry</td>
                  <td className="badge-ok">Verified Hardware</td>
                  <td>Query 0x0C -&gt; Input Report 0x03 (0x4010)</td>
                  <td>Real-Time Hardware</td>
                </tr>
                <tr>
                  <td>RGB Backlight Strip</td>
                  <td className="badge-warn">Unsupported by Hardware</td>
                  <td>Hidden in UI (X3 only has a DPI stage LED)</td>
                  <td>N/A</td>
                </tr>
              </tbody>
            </table>
          </div>
        </main>
      )}

      {/* VIEW 7: DIAGNOSTICS & OPERATION LOG */}
      {activeTab === 'diagnostics' && (
        <main className="tab-single-col">
          <div className="dash-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3>USB/HID Diagnostics &amp; Timestamped Operation Log</h3>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="dpi-apply-btn" type="button" onClick={() => setLogs([])}>
                  Clear Log
                </button>
                <button className="dpi-apply-btn" type="button" onClick={exportDiagnosticReport}>
                  Export Diagnostic JSON
                </button>
              </div>
            </div>
            <p className="muted-note" style={{ marginTop: 6 }}>
              Windows WebHID Note: Attack Shark X3 exposes Feature Reports on <code>mi_02&amp;col04</code> (<code>UsagePage=0x000B, Usage=0x0000</code>). Because <code>Usage=0x0000</code> yields <code>0</code> Feature ValueCaps in Windows <code>hid.dll</code>, Chrome WebHID blocks <code>sendFeatureReport</code>. The <strong>Native Bridge (`server.py`)</strong> calls Win32 <code>HidD_SetFeature</code> directly on <code>col04</code> with 100% verified delivery.
            </p>
            <div className="diag-log-box">
              {logs.length === 0 ? (
                <div className="muted-note">No hardware operations logged yet.</div>
              ) : (
                logs.map((l) => (
                  <div key={l.id} className="log-line">
                    [{l.timestamp}] <span className={l.direction === 'TX' ? 'tx' : 'rx'}>{l.direction}</span>{' '}
                    [{l.transport.toUpperCase()}] <strong>{l.summary}</strong>
                    {l.hex ? <code> — {l.hex}</code> : null}
                  </div>
                ))
              )}
            </div>
          </div>
        </main>
      )}

      {/* Macro Manager Modal */}
      {showMacroModal && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <div className="modal-header">
              <span>Macro Manager</span>
              <button
                className="collapse-btn"
                type="button"
                onClick={() => {
                  setRecordingMacro(false);
                  setShowMacroModal(false);
                }}
              >
                ×
              </button>
            </div>
            <div className="modal-body">
              <div className="macro-col">
                <div className="macro-subtitle">Macro List</div>
                <div className="macro-list">
                  {macros.map((m, idx) => (
                    <div
                      key={m.id}
                      className={`profile-item ${idx === activeMacroIdx ? 'active' : ''}`}
                      onClick={() => setActiveMacroIdx(idx)}
                    >
                      {m.name}
                    </div>
                  ))}
                </div>
                <div className="macro-btn-row">
                  <button
                    className="dpi-apply-btn"
                    type="button"
                    onClick={() => {
                      setMacros((prev) => [
                        ...prev,
                        { id: `mac-${Date.now()}`, name: `Macro${prev.length + 1}`, events: [] }
                      ]);
                      setActiveMacroIdx(macros.length);
                    }}
                  >
                    New
                  </button>
                  <button
                    className="dpi-apply-btn"
                    type="button"
                    onClick={() => {
                      if (macros.length <= 1) return;
                      setMacros((prev) => prev.filter((_, i) => i !== activeMacroIdx));
                      setActiveMacroIdx(0);
                    }}
                  >
                    Delete
                  </button>
                </div>
              </div>
              <div className="macro-col">
                <div className="macro-subtitle">Key Sequence</div>
                <div className="macro-events">
                  {(macros[activeMacroIdx]?.events || []).map((ev, i) => (
                    <div key={i} className="profile-item">
                      {ev}
                    </div>
                  ))}
                </div>
                <div className="macro-btn-row">
                  <button
                    className="dpi-apply-btn"
                    type="button"
                    onClick={() => setRecordingMacro((r) => !r)}
                  >
                    {recordingMacro ? 'Stop Record' : 'Start Record'}
                  </button>
                  <button
                    className="dpi-apply-btn"
                    type="button"
                    onClick={() =>
                      setMacros((prev) =>
                        prev.map((m, i) => (i === activeMacroIdx ? { ...m, events: [] } : m))
                      )
                    }
                  >
                    Clear Keys
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {toast && <div className="toast-msg">{toast}</div>}
    </div>
  );
};
