import React, { useEffect, useRef, useState } from 'react';
import { LiftOffDistanceMm, PollingRateHz } from '../protocol/x3Protocol';
import { ApplyTarget, MouseProfileData } from '../transport/types';

interface HardwareTesterLabProps {
  profile: MouseProfileData;
  updateProfileData: (updater: (prev: MouseProfileData) => MouseProfileData) => void;
  applyToHardware: (target: ApplyTarget, customData?: MouseProfileData) => Promise<void>;
}

interface ClickEventRecord {
  id: number;
  label: string;
  deltaMs: number | null;
  holdMs: number | null;
  time: string;
}

export const HardwareTesterLab: React.FC<HardwareTesterLabProps> = ({
  profile,
  updateProfileData,
  applyToHardware
}) => {
  // 1. Live Polling Rate (Hz) state
  const pollingPadRef = useRef<HTMLDivElement | null>(null);
  const reportTimestampsRef = useRef<number[]>([]);
  const [liveHz, setLiveHz] = useState<number>(0);
  const [peakHz, setPeakHz] = useState<number>(0);
  const [avgIntervalMs, setAvgIntervalMs] = useState<number>(0);
  const [jitterMs, setJitterMs] = useState<number>(0);
  const [sampleCount, setSampleCount] = useState<number>(0);

  // 2. Angle Snapping / Sensor Canvas state
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const isDrawingRef = useRef<boolean>(false);
  const strokePointsRef = useRef<Array<{ x: number; y: number }>>([]);
  const [axisLockPercent, setAxisLockPercent] = useState<number>(0);
  const [strokePointCount, setStrokePointCount] = useState<number>(0);

  // 3. Button Mapping & Debounce Click Tester state
  const lastClickTimeRef = useRef<number | null>(null);
  const mouseDownTimeRef = useRef<Record<number, number>>({});
  const clickTimestampsRef = useRef<number[]>([]);
  const [activeButtons, setActiveButtons] = useState<Record<string, boolean>>({});
  const [buttonCounts, setButtonCounts] = useState<Record<string, number>>({
    left: 0,
    right: 0,
    middle: 0,
    back: 0,
    forward: 0,
    wheelUp: 0,
    wheelDown: 0
  });
  const [lastDeltaMs, setLastDeltaMs] = useState<number | null>(null);
  const [minDeltaMs, setMinDeltaMs] = useState<number | null>(null);
  const [lastHoldMs, setLastHoldMs] = useState<number | null>(null);
  const [cps, setCps] = useState<number>(0);
  const [clickHistory, setClickHistory] = useState<ClickEventRecord[]>([]);

  // 4. DPI & LOD Swipe Distance / Cutoff state
  const [isMeasuringSwipe, setIsMeasuringSwipe] = useState<boolean>(false);
  const [swipeCountsX, setSwipeCountsX] = useState<number>(0);
  const [swipeCountsY, setSwipeCountsY] = useState<number>(0);
  const [lodCutoffs, setLodCutoffs] = useState<number>(0);
  const lastSwipeMoveTsRef = useRef<number>(0);

  // 5. Double-click & Scroll OS Attribute tester
  const [dblClickSuccess, setDblClickSuccess] = useState<number>(0);
  const [lastWheelDeltaY, setLastWheelDeltaY] = useState<number>(0);

  // Attach native pointerrawupdate on the Polling Rate pad for un-coalesced USB HID timing
  useEffect(() => {
    const el = pollingPadRef.current;
    if (!el) return;

    const handleRawPointer = (e: Event) => {
      const pe = e as PointerEvent;
      const coalesced =
        typeof pe.getCoalescedEvents === 'function' ? pe.getCoalescedEvents() : [pe];
      const now = performance.now();

      if (coalesced.length > 1) {
        for (const ce of coalesced) {
          const ts = ce.timeStamp > 0 ? ce.timeStamp : now;
          reportTimestampsRef.current.push(ts);
        }
      } else {
        const ts = pe.timeStamp > 0 ? pe.timeStamp : now;
        reportTimestampsRef.current.push(ts);
      }

      // Keep timestamps within the last 350ms
      const cutoff = (pe.timeStamp > 0 ? pe.timeStamp : now) - 350;
      while (reportTimestampsRef.current.length > 0 && reportTimestampsRef.current[0] < cutoff) {
        reportTimestampsRef.current.shift();
      }
    };

    // pointerrawupdate fires per USB report in Chromium browsers
    if ('onpointerrawupdate' in window) {
      el.addEventListener('pointerrawupdate', handleRawPointer);
    } else {
      el.addEventListener('pointermove', handleRawPointer);
    }

    const timer = window.setInterval(() => {
      const pts = reportTimestampsRef.current;
      if (pts.length < 4) {
        setLiveHz(0);
        return;
      }
      const intervals: number[] = [];
      for (let i = 1; i < pts.length; i++) {
        const dt = pts[i] - pts[i - 1];
        if (dt > 0.15 && dt < 40) {
          intervals.push(dt);
        }
      }
      if (intervals.length < 3) {
        setLiveHz(0);
        return;
      }
      const avgDt = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const variance =
        intervals.reduce((acc, v) => acc + Math.abs(v - avgDt), 0) / intervals.length;
      const currentHz = Math.round(1000 / avgDt);

      setLiveHz(currentHz);
      setPeakHz((prev) => Math.max(prev, currentHz));
      setAvgIntervalMs(Number(avgDt.toFixed(2)));
      setJitterMs(Number(variance.toFixed(2)));
      setSampleCount((prev) => prev + intervals.length);
    }, 120);

    return () => {
      el.removeEventListener('pointerrawupdate', handleRawPointer);
      el.removeEventListener('pointermove', handleRawPointer);
      window.clearInterval(timer);
    };
  }, []);

  // Initialize Sensor Drawing Canvas
  const clearCanvas = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.fillStyle = '#0d0d0d';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Draw subtle reference grid lines for Angle Snapping verification
    ctx.strokeStyle = '#1f1f1f';
    ctx.lineWidth = 1;
    for (let x = 0; x <= canvas.width; x += 40) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, canvas.height);
      ctx.stroke();
    }
    for (let y = 0; y <= canvas.height; y += 40) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(canvas.width, y);
      ctx.stroke();
    }
    strokePointsRef.current = [];
    setAxisLockPercent(0);
    setStrokePointCount(0);
  };

  useEffect(() => {
    clearCanvas();
  }, []);

  const handleCanvasPointerDown = (e: React.PointerEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    canvas.setPointerCapture(e.pointerId);
    isDrawingRef.current = true;
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    strokePointsRef.current = [{ x, y }];
  };

  const handleCanvasPointerMove = (e: React.PointerEvent<HTMLCanvasElement>) => {
    if (!isDrawingRef.current) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const rect = canvas.getBoundingClientRect();
    const events =
      typeof e.nativeEvent.getCoalescedEvents === 'function'
        ? e.nativeEvent.getCoalescedEvents()
        : [e.nativeEvent];

    for (const ev of events) {
      const x = ev.clientX - rect.left;
      const y = ev.clientY - rect.top;
      const pts = strokePointsRef.current;
      const prev = pts[pts.length - 1];
      if (!prev) continue;
      const dx = x - prev.x;
      const dy = y - prev.y;
      if (dx === 0 && dy === 0) continue;

      const isAxisAligned = Math.abs(dx) === 0 || Math.abs(dy) === 0;
      ctx.strokeStyle = isAxisAligned ? '#2ecc71' : '#3a9efd';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(prev.x, prev.y);
      ctx.lineTo(x, y);
      ctx.stroke();

      ctx.fillStyle = isAxisAligned ? '#2ecc71' : '#ffffff';
      ctx.fillRect(x - 1.5, y - 1.5, 3, 3);

      pts.push({ x, y });
    }

    // Calculate percentage of segments that are strictly horizontal or vertical (Angle Snapped)
    const pts = strokePointsRef.current;
    if (pts.length > 2) {
      let aligned = 0;
      let total = 0;
      for (let i = 1; i < pts.length; i++) {
        const dx = Math.abs(pts[i].x - pts[i - 1].x);
        const dy = Math.abs(pts[i].y - pts[i - 1].y);
        if (dx + dy === 0) continue;
        total++;
        if (dx === 0 || dy === 0) {
          aligned++;
        }
      }
      if (total > 0) {
        setAxisLockPercent(Math.round((aligned / total) * 100));
        setStrokePointCount(pts.length);
      }
    }
  };

  const handleCanvasPointerUp = (e: React.PointerEvent<HTMLCanvasElement>) => {
    isDrawingRef.current = false;
    const canvas = canvasRef.current;
    if (canvas && canvas.hasPointerCapture(e.pointerId)) {
      canvas.releasePointerCapture(e.pointerId);
    }
  };

  // Button & Debounce Tester Handlers
  const buttonNameFromMouseButton = (btn: number): { key: string; label: string } => {
    switch (btn) {
      case 0:
        return { key: 'left', label: 'Left Click (Btn 1)' };
      case 1:
        return { key: 'middle', label: 'Middle Click (Btn 3)' };
      case 2:
        return { key: 'right', label: 'Right Click (Btn 2)' };
      case 3:
        return { key: 'back', label: 'Backward (Btn 5)' };
      case 4:
        return { key: 'forward', label: 'Forward (Btn 4)' };
      default:
        return { key: `btn${btn}`, label: `Button ${btn}` };
    }
  };

  const handleTestZoneMouseDown = (e: React.MouseEvent<HTMLDivElement>) => {
    e.preventDefault();
    const now = performance.now();
    const { key, label } = buttonNameFromMouseButton(e.button);
    mouseDownTimeRef.current[e.button] = now;

    setActiveButtons((prev) => ({ ...prev, [key]: true }));
    setButtonCounts((prev) => ({ ...prev, [key]: (prev[key] || 0) + 1 }));

    let delta: number | null = null;
    if (lastClickTimeRef.current !== null) {
      delta = Number((now - lastClickTimeRef.current).toFixed(1));
      setLastDeltaMs(delta);
      setMinDeltaMs((prev) => (prev === null ? delta : Math.min(prev, delta!)));
    }
    lastClickTimeRef.current = now;

    // CPS rolling 1000ms window
    clickTimestampsRef.current.push(now);
    const cutoff = now - 1000;
    while (clickTimestampsRef.current.length > 0 && clickTimestampsRef.current[0] < cutoff) {
      clickTimestampsRef.current.shift();
    }
    setCps(clickTimestampsRef.current.length);

    setClickHistory((prev) => [
      {
        id: Date.now() + Math.random(),
        label,
        deltaMs: delta,
        holdMs: null,
        time: new Date().toLocaleTimeString()
      },
      ...prev.slice(0, 7)
    ]);
  };

  const handleTestZoneMouseUp = (e: React.MouseEvent<HTMLDivElement>) => {
    e.preventDefault();
    const now = performance.now();
    const { key } = buttonNameFromMouseButton(e.button);
    setActiveButtons((prev) => ({ ...prev, [key]: false }));

    const downTs = mouseDownTimeRef.current[e.button];
    if (downTs !== undefined) {
      const hold = Number((now - downTs).toFixed(1));
      setLastHoldMs(hold);
      setClickHistory((prev) =>
        prev.map((item, idx) => (idx === 0 && item.holdMs === null ? { ...item, holdMs: hold } : item))
      );
    }
  };

  const handleTestZoneWheel = (e: React.WheelEvent<HTMLDivElement>) => {
    const isUp = e.deltaY < 0;
    const key = isUp ? 'wheelUp' : 'wheelDown';
    setLastWheelDeltaY(Math.round(Math.abs(e.deltaY)));
    setButtonCounts((prev) => ({ ...prev, [key]: (prev[key] || 0) + 1 }));
    setActiveButtons((prev) => ({ ...prev, [key]: true }));
    window.setTimeout(() => {
      setActiveButtons((prev) => ({ ...prev, [key]: false }));
    }, 140);
  };

  // Quick Hardware Switch Helpers
  const quickSetPolling = (hz: PollingRateHz) => {
    const next = { ...profile, pollingRate: hz };
    updateProfileData(() => next);
    setPeakHz(0);
    setSampleCount(0);
    reportTimestampsRef.current = [];
    applyToHardware('polling', next);
  };

  const quickToggleSensor = (field: 'angleSnap' | 'rippleControl' | 'motionSync') => {
    const next = { ...profile, [field]: !profile[field] };
    updateProfileData(() => next);
    applyToHardware('sensor', next);
  };

  const quickSetLod = (lod: LiftOffDistanceMm) => {
    const next = { ...profile, lod };
    updateProfileData(() => next);
    applyToHardware('sensor', next);
  };

  const quickSetDebounce = (ms: number) => {
    const next = { ...profile, debounce: ms };
    updateProfileData(() => next);
    setMinDeltaMs(null);
    applyToHardware('debounce', next);
  };

  const pollingMatched =
    liveHz > 0 && Math.abs(liveHz - profile.pollingRate) <= Math.max(35, profile.pollingRate * 0.18);

  return (
    <main className="tab-single-col">
      {/* Header Banner */}
      <div className="dash-card" style={{ marginBottom: 18 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3>Interactive Hardware Verification Lab</h3>
            <p className="muted-note" style={{ marginTop: 4 }}>
              Test and verify every Attack Shark X3 hardware feature in real time: Polling Rate (Hz), Angle Snapping, Ripple Control, Motion Sync, Button Mapping, Debounce Time, DPI &amp; Lift-Off Distance.
            </p>
          </div>
          <span className="badge-ok" style={{ fontSize: 13 }}>
            Active: {profile.stages[profile.activeStage]} DPI · {profile.pollingRate}Hz · {profile.debounce}ms Debounce
          </span>
        </div>
      </div>

      <div className="dashboard-grid" style={{ padding: 0 }}>
        {/* 1. LIVE POLLING RATE (HZ) METER */}
        <div className="dash-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3>1. Live Polling Rate (Hz) Meter</h3>
            <span className={pollingMatched ? 'badge-ok' : 'muted-note'}>
              {liveHz > 0
                ? pollingMatched
                  ? `✓ Matches ${profile.pollingRate}Hz Target`
                  : `Measuring... (Move faster in circles)`
                : `Target: ${profile.pollingRate}Hz`}
            </span>
          </div>
          <p className="muted-note" style={{ marginBottom: 10 }}>
            Switch between <strong>125Hz</strong> and <strong>1000Hz</strong> below, then swirl your cursor rapidly inside the test pad to measure raw USB report frequency.
          </p>

          <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
            {([125, 250, 500, 1000] as PollingRateHz[]).map((hz) => (
              <button
                key={hz}
                type="button"
                className={`dpi-apply-btn ${profile.pollingRate === hz ? 'active-pill' : ''}`}
                style={{
                  background: profile.pollingRate === hz ? '#3a9efd' : '#262626',
                  borderColor: profile.pollingRate === hz ? '#62b4ff' : '#3a3a3a',
                  fontWeight: profile.pollingRate === hz ? 700 : 500
                }}
                onClick={() => quickSetPolling(hz)}
              >
                Set {hz}Hz
              </button>
            ))}
            <button
              type="button"
              className="dpi-apply-btn"
              onClick={() => {
                setPeakHz(0);
                setSampleCount(0);
                setLiveHz(0);
              }}
            >
              Reset Peak
            </button>
          </div>

          <div className="stat-kv" style={{ marginBottom: 12 }}>
            <div>
              <span>Live Polling Rate</span>
              <strong style={{ fontSize: 22, color: '#3a9efd' }}>{liveHz} Hz</strong>
            </div>
            <div>
              <span>Peak Measured</span>
              <strong style={{ fontSize: 22, color: '#2ecc71' }}>{peakHz} Hz</strong>
            </div>
            <div>
              <span>Avg Report Interval</span>
              <strong>{avgIntervalMs > 0 ? `${avgIntervalMs} ms` : '—'}</strong>
            </div>
            <div>
              <span>Motion Sync Jitter</span>
              <strong>{jitterMs > 0 ? `±${jitterMs} ms` : '—'}</strong>
            </div>
          </div>

          <div
            ref={pollingPadRef}
            style={{
              height: 135,
              borderRadius: 6,
              border: '1px dashed #3a9efd',
              background: 'radial-gradient(circle at center, #16222f 0%, #0e0e0e 100%)',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'crosshair',
              userSelect: 'none'
            }}
          >
            <div style={{ fontSize: 15, fontWeight: 700, color: '#e8e8e8' }}>
              Swirl Mouse Rapidly Inside This Box
            </div>
            <div className="muted-note" style={{ marginTop: 4 }}>
              125Hz ≈ 8.0ms interval · 250Hz ≈ 4.0ms · 500Hz ≈ 2.0ms · 1000Hz ≈ 1.0ms ({sampleCount} reports)
            </div>
          </div>
        </div>

        {/* 2. ANGLE SNAPPING & RIPPLE CONTROL CANVAS */}
        <div className="dash-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3>2. Sensor Canvas (Angle Snap &amp; Ripple)</h3>
            <span className={axisLockPercent >= 55 ? 'badge-ok' : 'muted-note'}>
              Straight-Line Lock: {axisLockPercent}% ({strokePointCount} pts)
            </span>
          </div>
          <p className="muted-note" style={{ marginBottom: 10 }}>
            Hold <strong>Left Click</strong> and draw horizontal or vertical lines. Green segments indicate strict 0°/90° pixel axis snapping from the PAW3395 sensor.
          </p>

          <div style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
            <button
              type="button"
              className="dpi-apply-btn"
              style={{
                background: profile.angleSnap ? '#2ecc71' : '#262626',
                color: profile.angleSnap ? '#0a0a0a' : '#fff',
                fontWeight: 700
              }}
              onClick={() => quickToggleSensor('angleSnap')}
            >
              Angle Snapping: {profile.angleSnap ? 'ON' : 'OFF'}
            </button>
            <button
              type="button"
              className="dpi-apply-btn"
              style={{
                background: profile.rippleControl ? '#3a9efd' : '#262626',
                fontWeight: 600
              }}
              onClick={() => quickToggleSensor('rippleControl')}
            >
              Ripple Control: {profile.rippleControl ? 'ON' : 'OFF'}
            </button>
            <button
              type="button"
              className="dpi-apply-btn"
              style={{
                background: profile.motionSync ? '#3a9efd' : '#262626',
                fontWeight: 600
              }}
              onClick={() => quickToggleSensor('motionSync')}
            >
              Motion Sync: {profile.motionSync ? 'ON' : 'OFF'}
            </button>
            <button type="button" className="dpi-apply-btn" onClick={clearCanvas}>
              Clear Canvas
            </button>
          </div>

          <canvas
            ref={canvasRef}
            width={520}
            height={175}
            onPointerDown={handleCanvasPointerDown}
            onPointerMove={handleCanvasPointerMove}
            onPointerUp={handleCanvasPointerUp}
            style={{
              width: '100%',
              height: 175,
              borderRadius: 6,
              border: '1px solid #2e2e2e',
              cursor: 'crosshair',
              touchAction: 'none'
            }}
          />
        </div>

        {/* 3. BUTTON MAPPING & DEBOUNCE CLICK SPEED TESTER */}
        <div className="dash-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3>3. Button Mapping &amp; Debounce Tester</h3>
            <span className="badge-ok">Debounce: {profile.debounce}ms · {cps} CPS</span>
          </div>
          <p className="muted-note" style={{ marginBottom: 10 }}>
            Click any mouse button or scroll inside the pad below to verify button remapping and measure click-to-click debounce intervals in milliseconds.
          </p>

          <div style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
            {[4, 8, 16, 30, 50].map((ms) => (
              <button
                key={ms}
                type="button"
                className="dpi-apply-btn"
                style={{
                  background: profile.debounce === ms ? '#3a9efd' : '#262626',
                  fontWeight: profile.debounce === ms ? 700 : 500
                }}
                onClick={() => quickSetDebounce(ms)}
              >
                Debounce {ms}ms
              </button>
            ))}
          </div>

          {/* Live Button Indicator Pills */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 6, marginBottom: 10 }}>
            {[
              { key: 'left', label: 'Left (Btn 1)' },
              { key: 'right', label: 'Right (Btn 2)' },
              { key: 'middle', label: 'Middle (Btn 3)' },
              { key: 'forward', label: 'Forward (Btn 4)' },
              { key: 'back', label: 'Back (Btn 5)' },
              { key: 'wheelUp', label: 'Scroll Up' },
              { key: 'wheelDown', label: 'Scroll Down' }
            ].map((b) => (
              <div
                key={b.key}
                style={{
                  padding: '6px 8px',
                  borderRadius: 4,
                  background: activeButtons[b.key] ? '#2ecc71' : '#1b1b1b',
                  color: activeButtons[b.key] ? '#0b0b0b' : '#d0d0d0',
                  border: '1px solid #303030',
                  fontSize: 12,
                  fontWeight: 600,
                  display: 'flex',
                  justifyContent: 'space-between'
                }}
              >
                <span>{b.label}</span>
                <strong>{buttonCounts[b.key] || 0}</strong>
              </div>
            ))}
          </div>

          <div className="stat-kv" style={{ marginBottom: 10 }}>
            <div>
              <span>Last Click Interval</span>
              <strong>{lastDeltaMs !== null ? `${lastDeltaMs} ms` : '—'}</strong>
            </div>
            <div>
              <span>Fastest Double-Click</span>
              <strong style={{ color: '#2ecc71' }}>{minDeltaMs !== null ? `${minDeltaMs} ms` : '—'}</strong>
            </div>
            <div>
              <span>Switch Hold Time</span>
              <strong>{lastHoldMs !== null ? `${lastHoldMs} ms` : '—'}</strong>
            </div>
            <div>
              <span>Click Speed (CPS)</span>
              <strong>{cps} clicks/sec</strong>
            </div>
          </div>

          <div
            onMouseDown={handleTestZoneMouseDown}
            onMouseUp={handleTestZoneMouseUp}
            onContextMenu={(e) => e.preventDefault()}
            onWheel={handleTestZoneWheel}
            style={{
              height: 95,
              borderRadius: 6,
              border: '1px dashed #2ecc71',
              background: '#131c16',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'pointer',
              userSelect: 'none'
            }}
          >
            <div style={{ fontSize: 14, fontWeight: 700, color: '#e8e8e8' }}>
              Click Left / Right / Middle / Side Buttons or Scroll Here
            </div>
            <div className="muted-note" style={{ marginTop: 4 }}>
              Right-click menu is disabled inside this box so you can test all buttons freely.
            </div>
          </div>

          {clickHistory.length > 0 && (
            <div style={{ marginTop: 8, fontSize: 12, color: '#9a9a9a' }}>
              Latest: <strong>{clickHistory[0].label}</strong>
              {clickHistory[0].deltaMs !== null ? ` · Δ ${clickHistory[0].deltaMs}ms` : ''}
              {clickHistory[0].holdMs !== null ? ` · Hold ${clickHistory[0].holdMs}ms` : ''}
            </div>
          )}
        </div>

        {/* 4. DPI SENSITIVITY, LOD (1MM vs 2MM) & OS ATTRIBUTES TESTER */}
        <div className="dash-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3>4. DPI Distance, LOD &amp; OS Wheel Tester</h3>
            <span className="badge-ok">
              LOD: {profile.lod}mm · Stage {profile.activeStage + 1} ({profile.stages[profile.activeStage]} DPI)
            </span>
          </div>
          <p className="muted-note" style={{ marginBottom: 10 }}>
            Compare DPI pixel counts across stages, test <strong>1mm vs 2mm Lift-Off Distance (LOD)</strong> cutoffs when hovering slightly off the pad, or test OS Double-Click &amp; Wheel Speed.
          </p>

          <div style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
            <button
              type="button"
              className="dpi-apply-btn"
              style={{ background: profile.lod === 1 ? '#3a9efd' : '#262626', fontWeight: 700 }}
              onClick={() => quickSetLod(1)}
            >
              Set LOD: 1mm (Low Cutoff)
            </button>
            <button
              type="button"
              className="dpi-apply-btn"
              style={{ background: profile.lod === 2 ? '#3a9efd' : '#262626', fontWeight: 700 }}
              onClick={() => quickSetLod(2)}
            >
              Set LOD: 2mm (High Hover)
            </button>
            <button
              type="button"
              className="dpi-apply-btn"
              onClick={() => {
                setSwipeCountsX(0);
                setSwipeCountsY(0);
                setLodCutoffs(0);
              }}
            >
              Reset Counters
            </button>
          </div>

          <div className="stat-kv" style={{ marginBottom: 10 }}>
            <div>
              <span>Accumulated X Counts</span>
              <strong>{swipeCountsX} px</strong>
            </div>
            <div>
              <span>Accumulated Y Counts</span>
              <strong>{swipeCountsY} px</strong>
            </div>
            <div>
              <span>Lift-Off Cutoffs Detected</span>
              <strong style={{ color: '#f39c12' }}>{lodCutoffs} stops</strong>
            </div>
            <div>
              <span>OS Double-Clicks / Wheel Δ</span>
              <strong>
                {dblClickSuccess} dbl · {lastWheelDeltaY}px
              </strong>
            </div>
          </div>

          <div
            onMouseDown={() => {
              setIsMeasuringSwipe(true);
              setSwipeCountsX(0);
              setSwipeCountsY(0);
              lastSwipeMoveTsRef.current = performance.now();
            }}
            onMouseUp={() => setIsMeasuringSwipe(false)}
            onMouseLeave={() => setIsMeasuringSwipe(false)}
            onDoubleClick={() => setDblClickSuccess((p) => p + 1)}
            onMouseMove={(e) => {
              const now = performance.now();
              if (lastSwipeMoveTsRef.current > 0 && now - lastSwipeMoveTsRef.current > 85) {
                setLodCutoffs((c) => c + 1);
              }
              lastSwipeMoveTsRef.current = now;
              if (isMeasuringSwipe || e.buttons === 1) {
                setSwipeCountsX((x) => x + Math.abs(e.movementX));
                setSwipeCountsY((y) => y + Math.abs(e.movementY));
              }
            }}
            style={{
              height: 110,
              borderRadius: 6,
              border: '1px dashed #f39c12',
              background: '#1c1812',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'ew-resize',
              userSelect: 'none'
            }}
          >
            <div style={{ fontSize: 14, fontWeight: 700, color: '#e8e8e8' }}>
              Hold Left Click &amp; Swipe 5cm (Test DPI) · Lift Slightly While Moving (Test 1mm/2mm LOD)
            </div>
            <div className="muted-note" style={{ marginTop: 4 }}>
              Or Double-Click inside this box to verify Windows Double-Click Speed ({profile.doubleClickSpeed}ms).
            </div>
          </div>
        </div>
      </div>
    </main>
  );
};
