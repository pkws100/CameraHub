const {test, expect} = require('@playwright/test');

test.describe('echter Caddy-/MediaMTX-/H.264-Pfad', () => {
  test.skip(!process.env.RUN_SYNTHETIC_ACCEPTANCE, 'wird nur mit dem synthetischen Docker-Stack ausgeführt');

  test('H.264-Quellen, WHEP, HLS und Raster 1/2/4/6/11 durchlaufen den echten Gateway-Pfad', async ({page}) => {
    test.setTimeout(60000);
    const password = 'Synthetic-Acceptance-42!';
    const loopbackOrigin = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:18091';
    const origin = loopbackOrigin.replace('127.0.0.1', 'camera-hub.test');
    await page.goto(`${loopbackOrigin}/index.html`);
    const setup = await page.evaluate(async ({password}) => {
      const state = await (await fetch('/api/auth/state')).json();
      if (!state.setupRequired) return {ok: true};
      const response = await fetch('/api/auth/setup', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username: 'acceptance-owner', password})
      });
      return {ok: response.ok};
    }, {password});
    expect(setup.ok).toBeTruthy();
    const loopbackAuthentication = await page.evaluate(async ({password}) => {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username: 'acceptance-owner', password})
      });
      return {ok: response.ok, payload: await response.json()};
    }, {password});
    expect(loopbackAuthentication.ok).toBeTruthy();
    const detectionSetup = await page.evaluate(async ({csrfToken}) => {
      const headers = {'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken};
      const responses = [];
      for (let number = 1; number <= 7; number += 1) {
        const cameraId = `acceptance-${String(number).padStart(2, '0')}`;
        const zoneId = `${cameraId}-motion-zone`;
        const currentZones = await (
          await fetch(`/api/admin/cameras/${cameraId}/zones`)
        ).json();
        responses.push(await fetch(`/api/admin/cameras/${cameraId}/zones`, {
          method: 'PUT',
          headers,
          body: JSON.stringify({
            revision: currentZones.revision,
            zones: [{
              id: zoneId,
              name: 'Synthetische Bewegung',
              kind: 'alarm',
              enabled: true,
              points: [{x: 0, y: 0}, {x: 1, y: 0}, {x: 1, y: 1}, {x: 0, y: 1}]
            }]
          })
        }));
        responses.push(await fetch(`/api/admin/cameras/${cameraId}/detection`, {
          method: 'PUT',
          headers,
          body: JSON.stringify({
            enabled: true,
            schedules: [],
            zones: [{
              zoneId,
              enabled: true,
              sensitivity: 50,
              minAreaPercent: 0.1,
              confirmationSeconds: 0.3,
              quietSeconds: 2,
              cooldownSeconds: 2,
              snapshotEnabled: false,
              schedules: []
            }]
          })
        }));
      }
      responses.push(await fetch('/api/owner/detection', {
        method: 'PUT',
        headers,
        body: JSON.stringify({mode: 'observe'})
      }));
      const errors = await Promise.all(responses.map(async response =>
        response.ok ? null : (await response.json()).detail
      ));
      return {ok: responses.every(response => response.ok), errors};
    }, {csrfToken: loopbackAuthentication.payload.csrfToken});
    expect(detectionSetup.ok, JSON.stringify(detectionSetup.errors)).toBeTruthy();
    await page.goto(`${origin}/index.html`);
    const authentication = await page.evaluate(async ({password}) => {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username: 'acceptance-owner', password})
      });
      return {ok: response.ok, payload: await response.json()};
    }, {password});
    expect(authentication.ok).toBeTruthy();
    const state = authentication.payload;
    expect(state.authenticated).toBeTruthy();
    await page.reload();
    const cameras = await page.evaluate(async () => (await (await fetch('/api/cameras')).json()).cameras);
    expect(cameras).toHaveLength(11);
    const runId = Date.now().toString(36);

    for (const count of [1, 2, 4, 6, 11]) {
      const profileResult = await page.evaluate(async ({csrfToken, count, cameraIds, runId}) => {
        const response = await fetch('/api/display-profiles', {
          method: 'POST',
          headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken},
          body: JSON.stringify({
          name: `Raster ${count} ${runId}`,
            cameraIds
          })
        });
        return {ok: response.ok, profile: await response.json()};
      }, {csrfToken: state.csrfToken, count, cameraIds: cameras.slice(0, count).map(camera => camera.id), runId});
      expect(profileResult.ok).toBeTruthy();
      const profile = profileResult.profile;
      await page.goto(`${origin}/index.html?count=${count}#wall?profile=${encodeURIComponent(profile.id)}`);
      await expect(page.locator('.camera-card')).toHaveCount(count);
      await expect(page.locator('.camera-card .card-status[data-state="live"]')).toHaveCount(count, {timeout: 20000});
      const passiveHealth = await page.evaluate(async () => await (await fetch('/api/health')).json());
      expect(passiveHealth.cameras.slice(0, count).every(camera => camera.state === 'live')).toBeTruthy();
      expect(passiveHealth.runtime.processRssBytes).toBeGreaterThan(0);
      expect(passiveHealth.runtime.hlsSessions).toBeGreaterThanOrEqual(0);
      const boxes = await page.locator('.camera-card').evaluateAll(nodes => nodes.map(node => {
        const box = node.getBoundingClientRect();
        return {width: Math.round(box.width), height: Math.round(box.height), right: box.right, bottom: box.bottom};
      }));
      expect(Math.max(...boxes.map(box => box.width)) - Math.min(...boxes.map(box => box.width))).toBeLessThanOrEqual(1);
      expect(Math.max(...boxes.map(box => box.height)) - Math.min(...boxes.map(box => box.height))).toBeLessThanOrEqual(1);
    }

    const gatewayMedia = await page.evaluate(async () => {
      const whep = await fetch('/whep/acceptance-01/whep', {method: 'OPTIONS'});
      let hls = 0;
      let segmentBytes = 0;
      for (let attempt = 0; attempt < 8 && segmentBytes <= 1000; attempt += 1) {
        let url = '/hls/acceptance-01/index.m3u8';
        for (let depth = 0; depth < 4; depth += 1) {
          const response = await fetch(url, {cache: 'no-store'});
          hls = response.status;
          if (!response.ok) break;
          const type = response.headers.get('Content-Type') || '';
          if (!type.includes('mpegurl')) {
            segmentBytes = (await response.arrayBuffer()).byteLength;
            break;
          }
          const playlist = await response.text();
          const candidate = playlist.split(/\r?\n/).find(line => line && !line.startsWith('#'));
          if (!candidate) break;
          const resolved = new URL(candidate, new URL(url, location.origin));
          url = resolved.pathname + resolved.search;
        }
        if (segmentBytes <= 1000) {
          await new Promise(resolve => setTimeout(resolve, 300));
        }
      }
      return {whep: whep.status, hls, segmentBytes};
    });
    expect(gatewayMedia.whep).toBe(204);
    expect(gatewayMedia.hls).toBe(200);
    expect(gatewayMedia.segmentBytes).toBeGreaterThan(1000);

    await page.goto(`${origin}/index.html#overview`);
    await page.locator('.open-camera').first().click();
    await page.locator('#detail-hls-toggle').click();
    expect(await page.locator('#detail-status').getAttribute('data-state')).not.toBe('live');
    await expect(page.locator('#detail-status')).toHaveAttribute('data-state', 'live', {timeout: 20000});
    await expect(page.locator('#detail-status')).toContainText('HLS');
    await expect.poll(async () => page.evaluate(async () => {
      const status = await (await fetch('/api/detection/status')).json();
      return {state: status.worker.state, cameras: status.worker.activeCameras};
    }), {timeout: 35000}).toEqual({state: 'active', cameras: 7});
    await expect.poll(async () => page.evaluate(async () => {
      const result = await (await fetch('/api/events?status=all&eventType=zone.motion')).json();
      return result.events.length;
    }), {timeout: 35000}).toBeGreaterThanOrEqual(7);
    const workerResources = await page.evaluate(async () => (
      await (await fetch('/api/detection/status')).json()
    ).worker);
    expect(workerResources.cpuPercent).toBeLessThanOrEqual(400);
    expect(workerResources.memoryBytes).toBeLessThanOrEqual(1536 * 1024 * 1024);
    await expect(page.locator('#motion-alert-banner')).toBeHidden();
    await page.goto(`${loopbackOrigin}/index.html#system`);
    const stopped = await page.evaluate(async ({csrfToken}) => {
      const response = await fetch('/api/owner/detection', {
        method: 'PUT',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken},
        body: JSON.stringify({mode: 'off'})
      });
      return response.ok;
    }, {csrfToken: loopbackAuthentication.payload.csrfToken});
    expect(stopped).toBeTruthy();
    await expect.poll(async () => page.evaluate(async () => {
      const status = await (await fetch('/api/detection/status')).json();
      return status.worker.activeCameras;
    }), {timeout: 15000}).toBe(0);
  });
});
