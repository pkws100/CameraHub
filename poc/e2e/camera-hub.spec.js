const {test, expect} = require('@playwright/test');

const pixel = Buffer.from(
  '/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////2wBDAf//////////////////////////////////////////////////////////////////////////////////////wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAf/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIQAxAAAAH/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oACAEBAAEFAqf/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oACAEDAQE/Aaf/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oACAECAQE/Aaf/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oACAEBAAY/Aqf/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oACAEBAAE/IX//2gAMAwEAAgADAAAAEP/EABQRAQAAAAAAAAAAAAAAAAAAABD/2gAIAQMBAT8QH//EABQRAQAAAAAAAAAAAAAAAAAAABD/2gAIAQIBAT8QH//EABQQAQAAAAAAAAAAAAAAAAAAABD/2gAIAQEAAT8QH//Z',
  'base64'
);

function camera(index, stream = false) {
  return {
    id: `camera-${index}`,
    name: `Kamera ${index}`,
    lowPath: `camera-${index}-low`,
    highPath: `camera-${index}-high`,
    source: 'Synthetisches H.264',
    detailQuality: 'Hauptstream',
    enabled: true,
    position: index,
    managed: true,
    usesCredentials: false,
    externalSource: false,
    onDemand: false,
    highWebRTCCompatible: true,
    compatibilityRelay: false,
    streamMode: 'auto',
    displayMode: stream ? 'stream' : 'snapshot',
    snapshotPath: stream ? null : `/synthetic/${index}.jpg`,
    features: {audio: false, ptz: false, ptzAxes: []}
  };
}

async function mockApplication(page, count, {stream = false, profilePayload = null, explicitBlink = false} = {}) {
  const cameras = Array.from({length: count}, (_, index) => camera(index + 1, stream));
  if (explicitBlink && cameras[0]) Object.assign(cameras[0], {
    name: 'Blink Einfahrt',
    source: 'Blink Cloud · bei Bedarf',
    externalSource: true,
    onDemand: true,
    cloudProvider: 'blink',
    explicitLiveOnly: true,
    liveMaxSeconds: 300,
    displayMode: 'explicit',
    snapshotPath: '/synthetic/1.jpg',
    features: {audio: false, ptz: false, ptzAxes: [], clips: true}
  });
  await page.route('**/synthetic/*.jpg*', route => route.fulfill({status: 200, contentType: 'image/jpeg', body: pixel}));
  await page.route('**/hls/**', route => route.fulfill({
    status: 200,
    contentType: 'text/html',
    body: `<!doctype html><video autoplay muted></video><script>
      const video=document.querySelector('video');let ready=false;
      Object.defineProperties(video,{
        readyState:{get:()=>ready?4:0},
        paused:{get:()=>!ready},
        currentTime:{get:()=>ready?1:0}
      });
      setTimeout(()=>{ready=true},900);
    </script>`
  }));
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/auth/state') return route.fulfill({json: {
      authenticated: true,
      csrfToken: 'e2e-csrf',
      elevatedUntil: 9999999999,
      user: {id: 'owner', username: 'owner', displayName: 'E2E', role: 'owner'},
      permissions: {view: true, manageCameras: true, controlCameras: true, manageZones: true, discoverCameras: true, manageUsers: true}
    }});
    if (url.pathname === '/api/display-profiles') return route.fulfill({json: profilePayload || {profiles: [], cameraOptions: cameras.map(({id, name, enabled, position}) => ({id, name, enabled, position}))}});
    if (url.pathname === '/api/cameras') return route.fulfill({json: {cameras}});
    if (url.pathname === '/api/health') return route.fulfill({json: {mediaMTX: 'online', cameras: cameras.map(item => ({camera: item.id, state: 'live'}))}});
    if (url.pathname === '/api/detection/status') return route.fulfill({json: {mode: 'off', timezone: 'Europe/Berlin', configuredCameras: 0, configuredZones: 0, openMotionEvents: 0, worker: {state: 'paused', online: true, activeCameras: 0, processingDelayMs: 0}}});
    if (/^\/api\/admin\/cameras\/[^/]+\/zones$/.test(url.pathname)) return route.fulfill({json: {cameraId: url.pathname.split('/')[4], revision: 0, zones: []}});
    if (/^\/api\/admin\/cameras\/[^/]+\/detection$/.test(url.pathname)) return route.fulfill({json: {cameraId: url.pathname.split('/')[4], supported: true, enabled: false, schedules: [], zones: []}});
    if (url.pathname.includes('/lease')) {
      return route.request().method() === 'DELETE'
        ? route.fulfill({status: 204})
        : route.fulfill({json: {leaseId: `lease-${url.pathname.split('/')[3]}`, expiresIn: 90}});
    }
    if (url.pathname === '/api/owner/display-devices') return route.fulfill({json: {devices: [], profileOptions: []}});
    if (url.pathname.startsWith('/api/owner/webhooks')) return route.fulfill({json: {targets: []}});
    if (url.pathname.startsWith('/api/events')) return route.fulfill({json: {events: [], summary: {open: 0, pending: 0, resolved: 0}}});
    return route.fulfill({status: 404, json: {detail: 'e2e-unhandled'}});
  });
}

test('Alarmzonenerkennung ist standardmäßig aus und Browseralarm ist lokal quittierbar', async ({page}) => {
  await page.addInitScript(() => localStorage.setItem('pkws-motion-alerts', '1'));
  await mockApplication(page, 1);
  await page.route('**/api/detection/events/stream', route => route.fulfill({
    status: 200,
    contentType: 'text/event-stream',
    body: 'event: zone.motion\ndata: {"eventId":"motion-1","cameraId":"camera-1","cameraName":"Kamera 1","zoneName":"Tor","startedAt":"2026-07-27T10:00:00Z"}\n\n'
  }));
  await page.goto('/index.html#system');
  await expect(page.locator('#detection-mode')).toHaveValue('off');
  await expect(page.locator('#detection-worker-state')).toContainText('Pausiert');
  await expect(page.locator('#motion-alert-banner')).toBeVisible();
  await expect(page.locator('#motion-alert-title')).toContainText('Kamera 1 · Tor');
  await page.locator('#motion-alert-dismiss').click();
  await expect(page.locator('#motion-alert-banner')).toBeHidden();
});

test('Kamera- und Zonenerkennung bleiben konfigurierbar', async ({page}) => {
  await mockApplication(page, 1);
  let savedDetection = null;
  const zone = {id: 'zone-1', name: 'Tor', kind: 'alarm', enabled: true, points: [{x: .1, y: .1}, {x: .9, y: .1}, {x: .9, y: .9}]};
  await page.route('**/api/admin/cameras/camera-1/zones', route => route.request().method() === 'PUT'
    ? route.fulfill({json: {cameraId: 'camera-1', revision: 2, zones: [zone]}})
    : route.fulfill({json: {cameraId: 'camera-1', revision: 1, zones: [zone]}}));
  await page.route('**/api/admin/cameras/camera-1/detection', route => {
    if (route.request().method() === 'PUT') {
      savedDetection = route.request().postDataJSON();
      return route.fulfill({json: {cameraId: 'camera-1', supported: true, ...savedDetection}});
    }
    return route.fulfill({json: {
      cameraId: 'camera-1',
      supported: true,
      enabled: true,
      schedules: [],
      zones: [{zoneId: 'zone-1', name: 'Tor', kind: 'alarm', enabled: true, sensitivity: 50, minAreaPercent: 1.5, confirmationSeconds: 1, quietSeconds: 5, cooldownSeconds: 30, snapshotEnabled: false, schedules: []}]
    }});
  });
  await page.goto('/index.html#zones');
  await expect(page.locator('#detection-camera-enabled')).toBeChecked();
  await page.locator('.zone-detection-details').click();
  await page.locator('[data-field="sensitivity"]').fill('65');
  await page.locator('#zone-save').click();
  await expect.poll(() => savedDetection).not.toBeNull();
  expect(savedDetection.enabled).toBeTruthy();
  expect(savedDetection.zones[0].sensitivity).toBe(65);
  expect(savedDetection.zones[0].snapshotEnabled).toBeFalsy();
});

for (const count of [1, 2, 4, 6, 11]) {
  test(`Leitstellenraster bleibt bei ${count} Kameras gleichmäßig und vollständig`, async ({page}) => {
    await mockApplication(page, count);
    await page.goto('/index.html#overview');
    await expect(page.locator('.camera-card')).toHaveCount(count);
    await page.locator('#enter-wall-mode').click();
    await expect(page.locator('body')).toHaveClass(/wall-mode/);
    const boxes = await page.locator('.camera-card').evaluateAll(nodes => nodes.map(node => {
      const box = node.getBoundingClientRect();
      return {left: box.left, top: box.top, right: box.right, bottom: box.bottom, width: box.width, height: box.height};
    }));
    const widths = boxes.map(box => Math.round(box.width));
    const heights = boxes.map(box => Math.round(box.height));
    expect(Math.max(...widths) - Math.min(...widths)).toBeLessThanOrEqual(1);
    expect(Math.max(...heights) - Math.min(...heights)).toBeLessThanOrEqual(1);
    for (const box of boxes) {
      expect(box.left).toBeGreaterThanOrEqual(0);
      expect(box.top).toBeGreaterThanOrEqual(0);
      expect(box.right).toBeLessThanOrEqual(await page.evaluate(() => innerWidth));
      expect(box.bottom).toBeLessThanOrEqual(await page.evaluate(() => innerHeight));
    }
  });
}

test('HLS meldet Live erst nach einem nachgewiesenen Videoframe', async ({page}) => {
  await mockApplication(page, 1, {stream: true});
  await page.goto('/index.html#overview');
  await page.locator('.open-camera').click();
  await page.locator('#detail-hls-toggle').click();
  expect(await page.locator('#detail-status').getAttribute('data-state')).not.toBe('live');
  await expect(page.locator('#detail-status')).toHaveAttribute('data-state', 'live', {timeout: 5000});
  await expect(page.locator('#detail-status')).toContainText('HLS');
});

test('Blink bleibt in Übersicht und Leitstelle passiv und startet Live nur per Klick', async ({page}) => {
  const leases = [];
  page.on('request', request => {
    if (new URL(request.url()).pathname.endsWith('/lease') && request.method() === 'POST') {
      leases.push(request.url());
    }
  });
  await mockApplication(page, 1, {explicitBlink: true});
  await page.goto('/index.html#overview');
  await expect(page.locator('.card-snapshot')).toBeVisible();
  expect(leases).toHaveLength(0);
  await page.locator('#enter-wall-mode').click();
  await expect(page.locator('body')).toHaveClass(/wall-mode/);
  await page.waitForTimeout(250);
  expect(leases).toHaveLength(0);
  await page.locator('#exit-wall-mode').click();
  await page.locator('.open-camera').click();
  await expect(page.locator('#detail-start-explicit')).toBeVisible();
  await expect(page.locator('#detail-snapshot')).toBeVisible();
  expect(leases).toHaveLength(0);
  await page.locator('#detail-start-explicit').click();
  await expect.poll(() => leases.length).toBe(1);
});

test('deaktivierte Kameras bleiben im Profil-Editor sichtbar', async ({page}) => {
  await mockApplication(page, 2, {profilePayload: {
    profiles: [{id: 'profil-1', name: 'Tablet', cameraIds: ['camera-1', 'camera-2'], cameraModes: {'camera-1': 'auto', 'camera-2': 'low'}, schedules: []}],
    cameraOptions: [
      {id: 'camera-1', name: 'Kamera 1', enabled: true, position: 0},
      {id: 'camera-2', name: 'Kamera 2', enabled: false, position: 1}
    ]
  }});
  await page.goto('/index.html#overview');
  await page.locator('#manage-display-profiles').click();
  await page.locator('#profile-editor-select').selectOption('profil-1');
  await expect(page.locator('.profile-camera-row[data-enabled="false"]')).toHaveCount(1);
  await expect(page.locator('.profile-camera-row select')).toHaveCount(2);
});

test('Eigentümer verwalten Anzeigegeräte und priorisierte Profile', async ({page}) => {
  await mockApplication(page, 2, {profilePayload: {
    profiles: [
      {id: 'profil-1', name: 'Frühdienst', cameraIds: ['camera-1'], cameraModes: {'camera-1': 'high'}, schedules: []},
      {id: 'profil-2', name: 'Nachtdienst', cameraIds: ['camera-2'], cameraModes: {'camera-2': 'low'}, schedules: []}
    ],
    cameraOptions: [
      {id: 'camera-1', name: 'Kamera 1', enabled: true, position: 0},
      {id: 'camera-2', name: 'Kamera 2', enabled: true, position: 1}
    ]
  }});
  let saved = null;
  await page.route('**/api/owner/display-devices', async route => {
    if (route.request().method() === 'POST') {
      saved = route.request().postDataJSON();
      return route.fulfill({status: 201, json: {
        id: 'display-2',
        name: saved.name,
        enabled: saved.enabled,
        profileIds: saved.profileIds,
        profiles: []
      }});
    }
    return route.fulfill({json: {
      devices: [{
        id: 'display-1',
        name: 'Leitstellen-TV',
        enabled: true,
        paired: true,
        profileIds: ['profil-2', 'profil-1'],
        profiles: [
          {id: 'profil-2', name: 'Nachtdienst'},
          {id: 'profil-1', name: 'Frühdienst'}
        ]
      }],
      profileOptions: [
        {id: 'profil-1', name: 'Frühdienst'},
        {id: 'profil-2', name: 'Nachtdienst'}
      ]
    }});
  });
  await page.goto('/index.html#system');
  await expect(page.locator('.display-device-row')).toContainText('Leitstellen-TV');
  await expect(page.locator('.display-device-row')).toContainText('Nachtdienst → Frühdienst');
  await page.locator('#add-display-device').click();
  await page.locator('#display-device-form input[name="name"]').fill('Tablet Empfang');
  await page.getByRole('checkbox', {name: 'Frühdienst'}).check();
  await page.locator('#display-device-form button[type="submit"]').click();
  await expect.poll(() => saved).not.toBeNull();
  expect(saved).toEqual({
    name: 'Tablet Empfang',
    enabled: true,
    profileIds: ['profil-1']
  });
});
