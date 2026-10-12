/**
 * Attack Shark X3 Web Driver — Controller (app.js)
 * Faithfully replicates the native X3.exe desktop UI and communicates
 * with the local hardware bridge (server.py) via /api/status and /api/apply.
 */

const BUTTON_OPTIONS = [
  { id: 1, label: 'Left Click' },
  { id: 2, label: 'Right Click' },
  { id: 3, label: 'Middle Button' },
  { id: 5, label: 'Forward' },
  { id: 4, label: 'Backward' },
  { id: 6, label: 'DPI Loop' },
  { id: 7, label: 'DPI +' },
  { id: 8, label: 'DPI -' },
  { id: 9, label: 'Three Click (Fire)' },
  { id: 13, label: 'Play / Pause' },
  { id: 14, label: 'Next Track' },
  { id: 15, label: 'Previous Track' },
  { id: 10, label: 'Volume +' },
  { id: 11, label: 'Volume -' },
  { id: 12, label: 'Mute' },
  { id: 0, label: 'Disable' }
];

const DEFAULT_PROFILE_DATA = {
  stages: [800, 1600, 2400, 3200, 5000, 26000],
  stageColors: ['#ff0000', '#00ff00', '#0000ff', '#ffff00', '#00ffff', '#ff00ff'],
  activeStage: 1, // 1600 DPI (Stage 2, matching native screenshot)
  pollingRate: 1000,
  lod: 1,
  debounce: 8, // 8 MS
  rippleControl: false,
  angleSnap: false,
  motionSync: false,
  sleepMinutes: 1,
  pointerSpeed: 10,
  doubleClickSpeed: 500,
  scrollLines: 3,
  // 5 buttons shown in UI: 1=Left, 2=Right, 3=Middle, 4=Forward, 5=Backward
  buttons: [1, 2, 3, 5, 4]
};

const state = {
  connected: false,
  mode: 'Disconnected',
  battery: 90,
  charging: false,
  activeProfileIndex: 0,
  profiles: [
    { name: 'Profile1', data: JSON.parse(JSON.stringify(DEFAULT_PROFILE_DATA)) }
  ],
  macros: [
    { name: 'Macro1', events: ['Down: E', 'Delay: 20ms', 'Up: E'] }
  ],
  activeMacroIndex: 0,
  recordingMacro: false,
  seenEventCount: 0
};

function currentProfile() {
  return state.profiles[state.activeProfileIndex].data;
}

function saveLocalState() {
  try {
    localStorage.setItem('attackshark_x3_profiles_v2', JSON.stringify({
      activeProfileIndex: state.activeProfileIndex,
      profiles: state.profiles,
      macros: state.macros
    }));
  } catch (_) {}
}

function loadLocalState() {
  try {
    const raw = localStorage.getItem('attackshark_x3_profiles_v2');
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed.profiles) && parsed.profiles.length > 0) {
      state.profiles = parsed.profiles;
      state.activeProfileIndex = Math.min(parsed.activeProfileIndex || 0, state.profiles.length - 1);
    }
    if (Array.isArray(parsed.macros)) {
      state.macros = parsed.macros;
    }
  } catch (_) {}
}

function showToast(msg) {
  const el = document.getElementById('toastMsg');
  if (!el) return;
  el.textContent = msg;
  el.classList.remove('hidden');
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => el.classList.add('hidden'), 2400);
}

function appendLog(direction, label, hex) {
  const container = document.getElementById('hidLogEntries');
  if (!container) return;
  const line = document.createElement('div');
  line.className = 'log-line';
  const time = new Date().toLocaleTimeString();
  const dirClass = direction === 'TX' ? 'tx' : 'rx';
  line.innerHTML = `[${time}] <span class="${dirClass}">${direction}</span> <strong>${label}</strong>: ${hex}`;
  container.prepend(line);
}

// Convert DPI (50..26000) to visual slider percentage (non-linear curve like X3.exe so 800..5000 are well-spaced)
function dpiToVisualPercent(dpi) {
  const clamped = Math.max(50, Math.min(26000, dpi));
  // Piecewise mapping matching X3.exe slider visual positions
  if (clamped <= 5000) {
    return 6 + (clamped / 5000) * 28;
  }
  return 34 + ((clamped - 5000) / 21000) * 66;
}

function visualPercentToDpi(pct) {
  const p = Math.max(0, Math.min(100, pct));
  let raw;
  if (p <= 34) {
    raw = ((p - 6) / 28) * 5000;
  } else {
    raw = 5000 + ((p - 34) / 66) * 21000;
  }
  const stepped = Math.round(raw / 50) * 50;
  return Math.max(50, Math.min(26000, stepped));
}

function renderDpiColumns() {
  const container = document.getElementById('dpiColumns');
  if (!container) return;
  const prof = currentProfile();
  container.innerHTML = '';

  prof.stages.forEach((dpiVal, idx) => {
    const col = document.createElement('div');
    col.className = 'dpi-col';

    const pct = dpiToVisualPercent(dpiVal);

    const trackWrap = document.createElement('div');
    trackWrap.className = 'dpi-vtrack-wrap';
    trackWrap.title = `Drag to adjust Stage ${idx + 1} DPI (50 - 26000)`;
    trackWrap.innerHTML = `
      <div class="dpi-vtrack">
        <div class="dpi-vfill" style="height: ${pct}%;"></div>
        <div class="dpi-vthumb" style="bottom: ${pct}%;"></div>
      </div>
    `;

    // Vertical drag support
    const updateFromClientY = (clientY) => {
      const rect = trackWrap.getBoundingClientRect();
      const rel = 1 - (clientY - rect.top) / rect.height;
      const newDpi = visualPercentToDpi(rel * 100);
      prof.stages[idx] = newDpi;
      const newPct = dpiToVisualPercent(newDpi);
      trackWrap.querySelector('.dpi-vfill').style.height = `${newPct}%`;
      trackWrap.querySelector('.dpi-vthumb').style.bottom = `${newPct}%`;
      valInput.value = newDpi;
    };

    trackWrap.addEventListener('mousedown', (e) => {
      e.preventDefault();
      updateFromClientY(e.clientY);
      const onMove = (ev) => updateFromClientY(ev.clientY);
      const onUp = () => {
        window.removeEventListener('mousemove', onMove);
        window.removeEventListener('mouseup', onUp);
        saveLocalState();
      };
      window.addEventListener('mousemove', onMove);
      window.addEventListener('mouseup', onUp);
    });

    const stepLbl = document.createElement('div');
    stepLbl.className = 'dpi-step-label';
    stepLbl.textContent = '50';

    const valInput = document.createElement('input');
    valInput.type = 'text';
    valInput.className = 'dpi-val-input';
    valInput.value = dpiVal;
    valInput.addEventListener('change', () => {
      let num = parseInt(valInput.value, 10);
      if (isNaN(num)) num = 800;
      num = Math.max(50, Math.min(26000, Math.round(num / 50) * 50));
      prof.stages[idx] = num;
      valInput.value = num;
      renderDpiColumns();
      saveLocalState();
    });

    const dot = document.createElement('button');
    dot.type = 'button';
    dot.className = `dpi-stage-dot ${prof.activeStage === idx ? 'active' : ''}`;
    dot.title = `Select Stage ${idx + 1} (${dpiVal} DPI)`;
    dot.addEventListener('click', () => {
      prof.activeStage = idx;
      renderDpiColumns();
      updateMouseLedIndicator();
      saveLocalState();
      applyHardware('dpi');
    });

    col.appendChild(trackWrap);
    col.appendChild(stepLbl);
    col.appendChild(valInput);
    col.appendChild(dot);
    container.appendChild(col);
  });
}

function updateMouseLedIndicator() {
  const pill = document.getElementById('mouseLedPill');
  if (!pill) return;
  const prof = currentProfile();
  const colors = ['#ff2020', '#00d8ff', '#28ff50', '#ffe600', '#00ffff', '#ff00ff'];
  pill.setAttribute('fill', colors[prof.activeStage] || '#00d8ff');
}

function renderButtonSelects() {
  const prof = currentProfile();
  for (let i = 0; i < 5; i++) {
    const sel = document.getElementById(`btnSelect${i}`);
    if (!sel) continue;
    sel.innerHTML = '';
    BUTTON_OPTIONS.forEach((opt) => {
      const optionEl = document.createElement('option');
      optionEl.value = opt.id;
      optionEl.textContent = opt.label;
      if (prof.buttons[i] === opt.id) {
        optionEl.selected = true;
      }
      sel.appendChild(optionEl);
    });
  }
}

function updateHorizontalSliderFill(slider) {
  if (!slider) return;
  const min = parseFloat(slider.min) || 0;
  const max = parseFloat(slider.max) || 100;
  const val = parseFloat(slider.value) || 0;
  const pct = ((val - min) / (max - min)) * 100;
  slider.style.background = `linear-gradient(90deg, #ff0c0c ${pct}%, #484848 ${pct}%)`;
}

function renderRightControls() {
  const prof = currentProfile();

  // Polling Rate
  document.querySelectorAll('input[name="pollingRate"]').forEach((r) => {
    r.checked = parseInt(r.value, 10) === prof.pollingRate;
  });

  // Lift of Distance
  document.querySelectorAll('input[name="lod"]').forEach((r) => {
    r.checked = parseInt(r.value, 10) === prof.lod;
  });

  // Key Response Time (Debounce)
  const debSlider = document.getElementById('debounceSlider');
  const debBox = document.getElementById('debounceValueBox');
  if (debSlider && debBox) {
    debSlider.value = prof.debounce;
    debBox.textContent = `${prof.debounce} MS`;
    updateHorizontalSliderFill(debSlider);
  }

  // Ripple Control
  document.querySelectorAll('input[name="rippleControl"]').forEach((r) => {
    r.checked = (r.value === '1') === Boolean(prof.rippleControl);
  });

  // Angle Snap
  document.querySelectorAll('input[name="angleSnap"]').forEach((r) => {
    r.checked = (r.value === '1') === Boolean(prof.angleSnap);
  });

  // Motion Sync
  document.querySelectorAll('input[name="motionSync"]').forEach((r) => {
    r.checked = (r.value === '1') === Boolean(prof.motionSync);
  });

  // Mouse Attribute Sliders
  const ptrSlider = document.getElementById('ptrSpeedSlider');
  const dblSlider = document.getElementById('dblClickSlider');
  const scrSlider = document.getElementById('scrollLinesSlider');
  if (ptrSlider) {
    ptrSlider.value = prof.pointerSpeed || 10;
    document.getElementById('ptrSpeedVal').textContent = ptrSlider.value;
    updateHorizontalSliderFill(ptrSlider);
  }
  if (dblSlider) {
    dblSlider.value = prof.doubleClickSpeed || 500;
    document.getElementById('dblClickVal').textContent = `${dblSlider.value} ms`;
    updateHorizontalSliderFill(dblSlider);
  }
  if (scrSlider) {
    scrSlider.value = prof.scrollLines || 3;
    document.getElementById('scrollLinesVal').textContent = scrSlider.value;
    updateHorizontalSliderFill(scrSlider);
  }

  // Sleep Time
  const sleepSel = document.getElementById('sleepTimeSelect');
  if (sleepSel) {
    sleepSel.value = String(prof.sleepMinutes || 1);
    document.getElementById('sleepTimeLabel').textContent = `${sleepSel.value} Min`;
  }
}

function renderProfilesList() {
  const box = document.getElementById('profileListbox');
  if (!box) return;
  box.innerHTML = '';
  state.profiles.forEach((p, idx) => {
    const item = document.createElement('div');
    item.className = `profile-item ${idx === state.activeProfileIndex ? 'active' : ''}`;
    item.textContent = p.name;
    item.addEventListener('click', () => {
      state.activeProfileIndex = idx;
      renderAllUI();
      saveLocalState();
      applyHardware('all');
    });
    box.appendChild(item);
  });
}

function renderBattery() {
  const fill = document.getElementById('batteryFill');
  const txt = document.getElementById('batteryPercentText');
  if (fill) fill.style.width = `${Math.max(5, Math.min(100, state.battery))}%`;
  if (txt) {
    txt.textContent = state.charging ? `${state.battery}% ⚡` : `${state.battery}%`;
  }
}

function renderAllUI() {
  renderButtonSelects();
  renderProfilesList();
  renderDpiColumns();
  renderRightControls();
  renderBattery();
  updateMouseLedIndicator();
}

async function applyHardware(target = 'all') {
  const prof = currentProfile();
  // Send 6 button values: 5 from UI + slot 6 (DPI Cycle = 6)
  const buttonsPayload = [...prof.buttons, 6];

  const payload = {
    target,
    activeStage: prof.activeStage,
    stages: prof.stages,
    stageColors: prof.stageColors,
    pollingRate: prof.pollingRate,
    lod: prof.lod,
    debounce: prof.debounce,
    rippleControl: prof.rippleControl,
    angleSnap: prof.angleSnap,
    motionSync: prof.motionSync,
    sleepMinutes: prof.sleepMinutes,
    pointerSpeed: prof.pointerSpeed,
    doubleClickSpeed: prof.doubleClickSpeed,
    scrollLines: prof.scrollLines,
    buttons: buttonsPayload
  };

  try {
    const resp = await fetch('/api/apply', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await resp.json();
    if (Array.isArray(data.results)) {
      data.results.forEach((r) => {
        appendLog('TX', `${r.name} [${r.ok ? 'OK' : 'ERR'}]`, r.hex || '');
      });
    }
    if (typeof data.battery === 'number') {
      state.battery = data.battery;
      state.charging = Boolean(data.charging);
      renderBattery();
    }
    if (data.ok) {
      showToast(`Applied to Attack Shark X3 (${target.toUpperCase()})`);
    } else {
      showToast('Hardware write failed — check mouse connection');
    }
  } catch (err) {
    showToast('Server unreachable on port 3000');
  }
}

async function pollHardwareStatus() {
  try {
    const resp = await fetch('/api/status');
    const data = await resp.json();
    state.connected = Boolean(data.connected);
    state.mode = data.mode || 'Disconnected';

    const dot = document.getElementById('connDot');
    const txt = document.getElementById('connText');
    const wBtn = document.getElementById('wirelessBtn');

    if (state.connected) {
      dot.className = 'conn-dot online';
      txt.textContent = state.mode;
      wBtn.classList.add('online');
    } else {
      dot.className = 'conn-dot offline';
      txt.textContent = 'Mouse Disconnected';
      wBtn.classList.remove('online');
    }

    if (typeof data.battery === 'number') {
      state.battery = data.battery;
      state.charging = Boolean(data.charging);
      renderBattery();
    }

    if (Array.isArray(data.events) && data.events.length > state.seenEventCount) {
      const newEvents = data.events.slice(state.seenEventCount);
      state.seenEventCount = data.events.length;
      newEvents.forEach((ev) => {
        appendLog('RX', `Input Event (${ev.type})`, ev.bytes.join(' '));
      });
    }
  } catch (_) {}
}

async function queryBatteryNow() {
  try {
    const resp = await fetch('/api/query-battery', { method: 'POST' });
    const data = await resp.json();
    if (data.tx) {
      appendLog('TX', 'Status/Battery Query (0x0C)', data.tx.hex || '');
    }
    if (typeof data.battery === 'number') {
      state.battery = data.battery;
      state.charging = Boolean(data.charging);
      renderBattery();
      showToast(`Battery: ${state.battery}%`);
    }
  } catch (_) {}
}

function bindEvents() {
  // Collapsible Panel Headers
  document.querySelectorAll('.x3-panel-header').forEach((hdr) => {
    hdr.addEventListener('click', () => {
      const panelId = hdr.getAttribute('data-toggle');
      const panel = document.getElementById(panelId);
      if (panel) {
        panel.classList.toggle('collapsed');
      }
    });
  });

  // 5 Button Selects
  for (let i = 0; i < 5; i++) {
    const sel = document.getElementById(`btnSelect${i}`);
    if (!sel) continue;
    sel.addEventListener('change', () => {
      const prof = currentProfile();
      const newVal = parseInt(sel.value, 10);
      const nextButtons = [...prof.buttons];
      nextButtons[i] = newVal;

      // Safety check matching X3.exe: at least one button must remain Left Click (1)
      if (!nextButtons.includes(1)) {
        showToast('At least one button must be assigned to Left Click!');
        sel.value = String(prof.buttons[i]);
        return;
      }

      prof.buttons[i] = newVal;
      saveLocalState();
      applyHardware('buttons');
    });
  }

  // Center Mouse Callout Badges (1..5) highlight corresponding row
  document.querySelectorAll('.mouse-callout').forEach((badge) => {
    badge.addEventListener('click', () => {
      const idx = badge.getAttribute('data-btn-index');
      document.querySelectorAll('.btn-row').forEach((r) => r.classList.remove('highlight'));
      const row = document.querySelector(`.btn-row[data-btn-index="${idx}"]`);
      if (row) {
        row.classList.add('highlight');
        const sel = row.querySelector('select');
        if (sel) sel.focus();
        setTimeout(() => row.classList.remove('highlight'), 1600);
      }
    });
  });

  // DPI Apply Button
  document.getElementById('dpiApplyBtn').addEventListener('click', () => {
    applyHardware('dpi');
  });

  // Top Apply All Button
  document.getElementById('syncAllBtn').addEventListener('click', () => {
    applyHardware('all');
  });

  // Wireless Icon & Power Panel query battery
  document.getElementById('wirelessBtn').addEventListener('click', queryBatteryNow);
  document.getElementById('powerWidget').addEventListener('click', queryBatteryNow);

  // Polling Rate Radios
  document.querySelectorAll('input[name="pollingRate"]').forEach((r) => {
    r.addEventListener('change', () => {
      if (r.checked) {
        currentProfile().pollingRate = parseInt(r.value, 10);
        saveLocalState();
        applyHardware('polling');
      }
    });
  });

  // Lift Of Distance Radios
  document.querySelectorAll('input[name="lod"]').forEach((r) => {
    r.addEventListener('change', () => {
      if (r.checked) {
        currentProfile().lod = parseInt(r.value, 10);
        saveLocalState();
        applyHardware('sensor');
      }
    });
  });

  // Key Response Time Slider (Debounce)
  const debSlider = document.getElementById('debounceSlider');
  debSlider.addEventListener('input', () => {
    const val = parseInt(debSlider.value, 10);
    document.getElementById('debounceValueBox').textContent = `${val} MS`;
    updateHorizontalSliderFill(debSlider);
  });
  debSlider.addEventListener('change', () => {
    currentProfile().debounce = parseInt(debSlider.value, 10);
    saveLocalState();
    applyHardware('debounce');
  });

  // Ripple Control Radios
  document.querySelectorAll('input[name="rippleControl"]').forEach((r) => {
    r.addEventListener('change', () => {
      if (r.checked) {
        currentProfile().rippleControl = r.value === '1';
        saveLocalState();
        applyHardware('sensor');
      }
    });
  });

  // Angle Snap Radios
  document.querySelectorAll('input[name="angleSnap"]').forEach((r) => {
    r.addEventListener('change', () => {
      if (r.checked) {
        currentProfile().angleSnap = r.value === '1';
        saveLocalState();
        applyHardware('sensor');
      }
    });
  });

  // Motion Sync Radios
  document.querySelectorAll('input[name="motionSync"]').forEach((r) => {
    r.addEventListener('change', () => {
      if (r.checked) {
        currentProfile().motionSync = r.value === '1';
        saveLocalState();
        applyHardware('sensor');
      }
    });
  });

  // Mouse Attribute Sliders
  const ptrSlider = document.getElementById('ptrSpeedSlider');
  const dblSlider = document.getElementById('dblClickSlider');
  const scrSlider = document.getElementById('scrollLinesSlider');

  [ptrSlider, dblSlider, scrSlider].forEach((s) => {
    s.addEventListener('input', () => {
      updateHorizontalSliderFill(s);
      document.getElementById('ptrSpeedVal').textContent = ptrSlider.value;
      document.getElementById('dblClickVal').textContent = `${dblSlider.value} ms`;
      document.getElementById('scrollLinesVal').textContent = scrSlider.value;
    });
    s.addEventListener('change', () => {
      const prof = currentProfile();
      prof.pointerSpeed = parseInt(ptrSlider.value, 10);
      prof.doubleClickSpeed = parseInt(dblSlider.value, 10);
      prof.scrollLines = parseInt(scrSlider.value, 10);
      saveLocalState();
      applyHardware('mouse_attr');
    });
  });

  // Power Management Sleep Select
  const sleepSel = document.getElementById('sleepTimeSelect');
  sleepSel.addEventListener('change', () => {
    const val = parseInt(sleepSel.value, 10);
    currentProfile().sleepMinutes = val;
    document.getElementById('sleepTimeLabel').textContent = `${val} Min`;
    saveLocalState();
    applyHardware('power');
  });

  // Profile Toolbar Buttons
  document.getElementById('profAddBtn').addEventListener('click', () => {
    const nextNum = state.profiles.length + 1;
    state.profiles.push({
      name: `Profile${nextNum}`,
      data: JSON.parse(JSON.stringify(DEFAULT_PROFILE_DATA))
    });
    state.activeProfileIndex = state.profiles.length - 1;
    renderAllUI();
    saveLocalState();
    showToast(`Created Profile${nextNum}`);
  });

  document.getElementById('profDelBtn').addEventListener('click', () => {
    if (state.profiles.length <= 1) {
      showToast('Cannot delete the last profile');
      return;
    }
    state.profiles.splice(state.activeProfileIndex, 1);
    state.activeProfileIndex = Math.max(0, state.activeProfileIndex - 1);
    renderAllUI();
    saveLocalState();
  });

  document.getElementById('profRenBtn').addEventListener('click', () => {
    const cur = state.profiles[state.activeProfileIndex];
    const nextName = prompt('Rename Profile:', cur.name);
    if (nextName && nextName.trim()) {
      cur.name = nextName.trim();
      renderProfilesList();
      saveLocalState();
    }
  });

  document.getElementById('profExpBtn').addEventListener('click', () => {
    const cur = state.profiles[state.activeProfileIndex];
    const blob = new Blob([JSON.stringify(cur, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${cur.name}.json`;
    a.click();
  });

  document.getElementById('profImpBtn').addEventListener('click', () => {
    document.getElementById('profImpInput').click();
  });

  document.getElementById('profImpInput').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const imported = JSON.parse(reader.result);
        if (imported && imported.data) {
          state.profiles.push(imported);
          state.activeProfileIndex = state.profiles.length - 1;
          renderAllUI();
          saveLocalState();
          applyHardware('all');
        }
      } catch (_) {
        showToast('Invalid profile JSON');
      }
    };
    reader.readAsText(file);
  });

  document.getElementById('profResetBtn').addEventListener('click', () => {
    state.profiles[state.activeProfileIndex].data = JSON.parse(JSON.stringify(DEFAULT_PROFILE_DATA));
    renderAllUI();
    saveLocalState();
    applyHardware('all');
    showToast('Restored Factory Default Settings');
  });

  // HID Packet Drawer Toggle
  const drawer = document.getElementById('hidDrawer');
  document.getElementById('toggleLogBtn').addEventListener('click', () => {
    drawer.classList.toggle('hidden');
  });
  document.getElementById('closeLogBtn').addEventListener('click', () => {
    drawer.classList.add('hidden');
  });
  document.getElementById('clearLogBtn').addEventListener('click', () => {
    document.getElementById('hidLogEntries').innerHTML = '';
  });

  // Macro Manager Modal
  const macroModal = document.getElementById('macroModal');
  document.getElementById('macroManagerBtn').addEventListener('click', () => {
    renderMacros();
    macroModal.classList.remove('hidden');
  });
  document.getElementById('closeMacroModalBtn').addEventListener('click', () => {
    state.recordingMacro = false;
    macroModal.classList.add('hidden');
  });

  document.getElementById('newMacroBtn').addEventListener('click', () => {
    state.macros.push({ name: `Macro${state.macros.length + 1}`, events: [] });
    state.activeMacroIndex = state.macros.length - 1;
    renderMacros();
    saveLocalState();
  });

  document.getElementById('delMacroBtn').addEventListener('click', () => {
    if (state.macros.length <= 1) return;
    state.macros.splice(state.activeMacroIndex, 1);
    state.activeMacroIndex = 0;
    renderMacros();
    saveLocalState();
  });

  const recBtn = document.getElementById('recMacroBtn');
  recBtn.addEventListener('click', () => {
    state.recordingMacro = !state.recordingMacro;
    recBtn.textContent = state.recordingMacro ? 'Stop Record' : 'Start Record';
    recBtn.style.background = state.recordingMacro ? '#b80c0c' : '';
  });

  document.getElementById('clearMacroEventsBtn').addEventListener('click', () => {
    if (state.macros[state.activeMacroIndex]) {
      state.macros[state.activeMacroIndex].events = [];
      renderMacros();
      saveLocalState();
    }
  });

  window.addEventListener('keydown', (e) => {
    if (!state.recordingMacro) return;
    e.preventDefault();
    const m = state.macros[state.activeMacroIndex];
    if (m) {
      m.events.push(`Key: ${e.code} (20ms)`);
      renderMacros();
      saveLocalState();
    }
  });
}

function renderMacros() {
  const listEl = document.getElementById('macroList');
  const evEl = document.getElementById('macroEvents');
  if (!listEl || !evEl) return;
  listEl.innerHTML = '';
  state.macros.forEach((m, idx) => {
    const div = document.createElement('div');
    div.className = `profile-item ${idx === state.activeMacroIndex ? 'active' : ''}`;
    div.textContent = m.name;
    div.addEventListener('click', () => {
      state.activeMacroIndex = idx;
      renderMacros();
    });
    listEl.appendChild(div);
  });

  evEl.innerHTML = '';
  const cur = state.macros[state.activeMacroIndex];
  if (cur) {
    cur.events.forEach((ev) => {
      const row = document.createElement('div');
      row.className = 'profile-item';
      row.textContent = ev;
      evEl.appendChild(row);
    });
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadLocalState();
  renderAllUI();
  bindEvents();
  pollHardwareStatus();
  setInterval(pollHardwareStatus, 2500);
});
