(() => {
  'use strict';
  const $ = selector => document.querySelector(selector);
  const states = new Map();
  let deviceState = null;
  let refreshTimer = null;
  let clockTimer = null;

  class ApiError extends Error {
    constructor(status, code) { super(code); this.status = status; this.code = code; }
  }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.body) headers.set('Content-Type', 'application/json');
    const response = await fetch(path, {...options, headers, credentials: 'same-origin', cache: 'no-store'});
    if (response.status === 204) return null;
    let data = {};
    try { data = await response.json(); } catch {}
    if (!response.ok) throw new ApiError(response.status, data.detail || `http-${response.status}`);
    return data;
  }

  const whepUrl = path => `${location.origin}/whep/${encodeURIComponent(path)}/whep`;
  const hlsUrl = path => `${location.origin}/hls/${encodeURIComponent(path)}/?autoplay=true&muted=true&controls=false&playsInline=true`;

  function closeCamera(state) {
    clearTimeout(state.leaseTimer);
    clearTimeout(state.retryTimer);
    clearTimeout(state.hlsTimer);
    state.reader?.close();
    state.reader = null;
    state.video.pause();
    state.video.srcObject = null;
    state.frame.removeAttribute('src');
    if (state.leaseId) {
      api(`/api/display/cameras/${encodeURIComponent(state.camera.id)}/lease?leaseId=${encodeURIComponent(state.leaseId)}`, {method: 'DELETE'}).catch(() => {});
      state.leaseId = null;
    }
  }

  function closeAll() {
    states.forEach(closeCamera);
    states.clear();
    $('#display-grid').replaceChildren();
  }

  function status(state, text, transport = '') {
    state.placeholder.hidden = text.startsWith('Live');
    state.placeholder.querySelector('span').textContent = text;
    if (transport) state.transport.textContent = transport;
  }

  async function ensureLease(state) {
    if (state.leaseId) return;
    const lease = await api(`/api/display/cameras/${encodeURIComponent(state.camera.id)}/lease`, {method: 'POST'});
    state.leaseId = lease.leaseId;
    const renew = async () => {
      try {
        await api(`/api/display/cameras/${encodeURIComponent(state.camera.id)}/lease?leaseId=${encodeURIComponent(state.leaseId)}`, {method: 'PUT'});
        state.leaseTimer = setTimeout(renew, 45000);
      } catch { state.leaseId = null; }
    };
    state.leaseTimer = setTimeout(renew, 45000);
  }

  function watchHls(state) {
    if (state.frame.hidden) return;
    const video = state.frame.contentDocument?.querySelector('video');
    if (video && video.readyState >= 2 && !video.paused && video.currentTime > 0) {
      status(state, 'Live', state.transportLabel);
      return;
    }
    state.hlsChecks += 1;
    if (state.hlsChecks >= 60) {
      status(state, 'HLS nicht verfügbar', `${state.mode} · HLS-Fehler`);
      return;
    }
    state.hlsTimer = setTimeout(() => watchHls(state), 500);
  }

  async function startHls(state, reason = '', path = state.camera.highPath || state.camera.lowPath) {
    try { await ensureLease(state); }
    catch (error) {
      status(state, 'Zugriff nicht möglich', `${state.mode} · ${error.code}`);
      return;
    }
    state.reader?.close();
    state.reader = null;
    state.video.hidden = true;
    state.frame.hidden = false;
    state.hlsChecks = 0;
    state.transportLabel = `${state.mode} · HLS${reason ? ` · ${reason}` : ''}`;
    status(state, 'HLS wird aufgebaut', state.transportLabel);
    state.frame.src = hlsUrl(path);
  }

  async function startWebRtc(state, path, mode, allowHlsFallback) {
    try { await ensureLease(state); }
    catch (error) { status(state, 'Zugriff nicht möglich', `${mode} · ${error.code}`); return; }
    state.frame.hidden = true;
    state.video.hidden = false;
    status(state, 'Verbindung wird aufgebaut', `${mode} · WebRTC`);
    let reader;
    reader = new MediaMTXWebRTCReader({
      url: whepUrl(path), user: '', pass: '', token: '',
      onTrack: event => {
        if (state.reader !== reader) return;
        state.video.srcObject = event.streams[0];
        state.video.play().catch(() => status(state, 'Zum Start antippen', `${mode} · WebRTC`));
      },
      onError: () => {
        if (state.reader !== reader) return;
        state.reader?.close();
        state.reader = null;
        if (allowHlsFallback) startHls(state, 'WebRTC-Fallback', path);
        else status(state, 'Stream nicht verfügbar', `${mode} · kein stiller Qualitätswechsel`);
      }
    });
    state.reader = reader;
  }

  async function startCamera(state) {
    const camera = state.camera;
    const mode = camera.streamMode || 'auto';
    state.mode = mode;
    if (camera.displayMode === 'snapshot' || camera.displayMode === 'explicit') {
      state.video.hidden = true;
      state.snapshot.hidden = false;
      state.snapshot.onload = () => status(
        state,
        camera.displayMode === 'explicit' ? 'Letzte Vorschau' : 'Live',
        camera.displayMode === 'explicit' ? 'Blink · kein automatischer Livezugriff' : `${mode} · Snapshot`
      );
      state.snapshot.onerror = () => status(state, 'Vorschau nicht verfügbar', `${mode} · Snapshot`);
      state.snapshot.src = `${camera.snapshotPath}?t=${Date.now()}`;
      return;
    }
    if (mode === 'hls') return startHls(state);
    if (mode === 'high') {
      if (camera.highWebRTCCompatible !== false) return startWebRtc(state, camera.highPath, 'high', true);
      return startHls(state, 'Hauptstream nicht WebRTC-kompatibel');
    }
    if (mode === 'low') return startWebRtc(state, camera.lowPath, 'low', false);
    return startWebRtc(state, camera.lowPath, 'auto', true);
  }

  function gridShape(count) {
    const width = Math.max(1, innerWidth), height = Math.max(1, innerHeight);
    let best = {columns: 1, rows: Math.max(1, count), score: Infinity};
    for (let columns = 1; columns <= Math.min(8, Math.max(1, count)); columns += 1) {
      const rows = Math.ceil(Math.max(1, count) / columns);
      const aspect = (width / columns) / (height / rows);
      const empty = (columns * rows - count) / (columns * rows);
      const score = Math.abs(Math.log(aspect / (16 / 9))) + empty * .18;
      if (score < best.score) best = {columns, rows, score};
    }
    return best;
  }

  function applyGridShape() {
    const shape = gridShape(states.size);
    $('#display-grid').style.setProperty('--columns', shape.columns);
    $('#display-grid').style.setProperty('--rows', shape.rows);
  }

  function renderCamera(camera) {
    const fragment = $('#display-camera-template').content.cloneNode(true);
    const card = fragment.querySelector('.display-camera');
    const state = {
      camera,
      card,
      video: card.querySelector('video'),
      snapshot: card.querySelector('img'),
      frame: card.querySelector('iframe'),
      placeholder: card.querySelector('.display-placeholder'),
      transport: card.querySelector('.display-transport'),
      reader: null,
      leaseId: null,
      leaseTimer: null,
      retryTimer: null,
      hlsTimer: null,
      hlsChecks: 0,
      mode: camera.streamMode || 'auto',
      transportLabel: ''
    };
    card.querySelector('.display-camera-name').textContent = camera.name;
    state.video.addEventListener('playing', () => status(state, 'Live', `${state.mode} · WebRTC`));
    state.video.addEventListener('click', () => state.video.play().catch(() => {}));
    state.frame.addEventListener('load', () => watchHls(state));
    states.set(camera.id, state);
    $('#display-grid').append(fragment);
    startCamera(state);
  }

  function showPair() {
    closeAll();
    $('#pair-view').hidden = false;
    $('#idle-view').hidden = true;
    $('#live-view').hidden = true;
  }

  function updateClock() {
    $('#idle-clock').textContent = new Intl.DateTimeFormat('de-DE', {hour: '2-digit', minute: '2-digit', second: '2-digit'}).format(new Date());
  }

  function showIdle(state) {
    closeAll();
    $('#pair-view').hidden = true;
    $('#idle-view').hidden = false;
    $('#live-view').hidden = true;
    $('#idle-device').textContent = state.device.name;
    $('#idle-next').textContent = state.nextProfileStart
      ? `Nächstes Profil „${state.nextProfileName}“: ${new Intl.DateTimeFormat('de-DE', {weekday: 'long', hour: '2-digit', minute: '2-digit'}).format(new Date(state.nextProfileStart))}`
      : 'Derzeit ist kein Profil aktiv.';
    updateClock();
    clearInterval(clockTimer);
    clockTimer = setInterval(updateClock, 1000);
  }

  async function showLive(state) {
    clearInterval(clockTimer);
    $('#pair-view').hidden = true;
    $('#idle-view').hidden = true;
    $('#live-view').hidden = false;
    $('#display-device-name').textContent = state.device.name;
    $('#display-profile-name').textContent = state.profile.name;
    closeAll();
    const data = await api('/api/display/cameras');
    (data.cameras || []).forEach(renderCamera);
    applyGridShape();
  }

  async function refresh() {
    clearTimeout(refreshTimer);
    try {
      const state = await api('/api/display/state');
      const changed = !deviceState
        || deviceState.active !== state.active
        || deviceState.profile?.id !== state.profile?.id
        || deviceState.configRevision !== state.configRevision;
      if (changed) {
        if (state.active) await showLive(state);
        else showIdle(state);
      }
      deviceState = state;
      refreshTimer = setTimeout(refresh, 30000);
    } catch (error) {
      if (error.status === 401) showPair();
      else {
        deviceState = null;
        refreshTimer = setTimeout(refresh, 10000);
      }
    }
  }

  $('#pair-form').addEventListener('submit', async event => {
    event.preventDefault();
    const form = event.currentTarget;
    $('#pair-error').textContent = '';
    try {
      await api('/api/display/pair', {method: 'POST', body: JSON.stringify({code: form.elements.code.value})});
      form.reset();
      deviceState = null;
      await refresh();
    } catch (error) {
      $('#pair-error').textContent = error.code === 'display-pair-rate-limited'
        ? 'Zu viele Versuche. Bitte warten Sie zehn Minuten.'
        : 'Der Code ist ungültig oder abgelaufen.';
    }
  });

  $('#display-fullscreen').addEventListener('click', () => document.documentElement.requestFullscreen?.().catch(() => {}));
  $('#display-logout').addEventListener('click', async () => {
    if (!confirm('Dieses Anzeigegerät wirklich neu koppeln?')) return;
    try { await api('/api/display/logout', {method: 'POST'}); } catch {}
    deviceState = null;
    showPair();
  });
  addEventListener('resize', applyGridShape, {passive: true});
  addEventListener('pagehide', closeAll);
  refresh();
})();
