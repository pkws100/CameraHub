const {test, expect} = require('@playwright/test');

async function mockDisplayApi(page, initialState, cameras = []) {
  let state = initialState;
  let cameraRequests = 0;
  let leaseRequests = 0;
  await page.route('**/reader.js', route => route.fulfill({
    contentType: 'application/javascript',
    body: `window.MediaMTXWebRTCReader=class{
      constructor(options){this.options=options;setTimeout(()=>options.onError('synthetic failure'),20)}
      close(){}
    };`
  }));
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
      setTimeout(()=>{ready=true},100);
    </script>`
  }));
  await page.route('**/api/**', async route => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === '/api/display/state') {
      return state
        ? route.fulfill({json: state})
        : route.fulfill({status: 401, json: {detail: 'display-authentication-required'}});
    }
    if (path === '/api/display/pair') {
      const body = request.postDataJSON();
      if (body.code !== '12345678') {
        return route.fulfill({status: 400, json: {detail: 'display-pair-code-invalid'}});
      }
      state = {
        paired: true,
        device: {id: 'display-1', name: 'Leitstellen-TV'},
        timezone: 'Europe/Berlin',
        active: false,
        profile: null,
        nextProfileStart: '2026-07-27T06:00:00+00:00',
        nextProfileName: 'Frühdienst'
      };
      return route.fulfill({json: state});
    }
    if (path === '/api/display/cameras') {
      cameraRequests += 1;
      return route.fulfill({json: {
        active: true,
        profile: state.profile,
        cameras
      }});
    }
    if (path.includes('/lease')) {
      if (request.method() === 'POST') leaseRequests += 1;
      return request.method() === 'DELETE'
        ? route.fulfill({status: 204})
        : route.fulfill({json: {leaseId: 'display-lease', expiresIn: 90}});
    }
    if (path === '/api/display/logout') {
      state = null;
      return route.fulfill({json: {ok: true}});
    }
    return route.fulfill({status: 404, json: {detail: 'e2e-unhandled'}});
  });
  return {
    cameraRequests: () => cameraRequests,
    leaseRequests: () => leaseRequests
  };
}

test('Kopplung und privater Ruhebildschirm laden keine Kameradaten', async ({page}) => {
  const mock = await mockDisplayApi(page, null);
  await page.goto('/display.html');
  await expect(page.locator('#pair-view')).toBeVisible();
  await page.locator('#pair-form input[name="code"]').fill('12345678');
  await page.locator('#pair-form button[type="submit"]').click();
  await expect(page.locator('#idle-view')).toBeVisible();
  await expect(page.locator('#idle-device')).toHaveText('Leitstellen-TV');
  await expect(page.locator('#idle-next')).toContainText('Frühdienst');
  expect(mock.cameraRequests()).toBe(0);
  expect(mock.leaseRequests()).toBe(0);
  await expect(page.locator('#display-grid .display-camera')).toHaveCount(0);
});

test('aktive Anzeige beachtet auto, high, low und hls ohne stillen Qualitätswechsel', async ({page}) => {
  const baseCamera = {
    source: 'Synthetisch',
    enabled: true,
    externalSource: false,
    onDemand: false,
    displayMode: 'stream',
    highWebRTCCompatible: true,
    lowPath: 'low',
    highPath: 'high',
    features: {audio: false, ptz: false, ptzAxes: []}
  };
  const modes = ['auto', 'high', 'low', 'hls'];
  const cameras = modes.map((streamMode, index) => ({
    ...baseCamera,
    id: `camera-${index + 1}`,
    name: `Kamera ${streamMode}`,
    lowPath: `camera-${index + 1}-low`,
    highPath: `camera-${index + 1}-high`,
    streamMode
  }));
  const mock = await mockDisplayApi(page, {
    paired: true,
    device: {id: 'display-1', name: 'Leitstellen-TV'},
    timezone: 'Europe/Berlin',
    active: true,
    profile: {id: 'profile-1', name: 'Nachtwache'},
    nextProfileStart: null,
    nextProfileName: null
  }, cameras);
  await page.goto('/display.html');
  await expect(page.locator('#live-view')).toBeVisible();
  await expect(page.locator('.display-camera')).toHaveCount(4);
  expect(mock.cameraRequests()).toBe(1);
  await expect.poll(() => mock.leaseRequests()).toBe(4);
  await expect(page.locator('.display-camera').nth(0).locator('.display-transport')).toContainText('auto · HLS');
  await expect(page.locator('.display-camera').nth(1).locator('.display-transport')).toContainText('high · HLS');
  await expect(page.locator('.display-camera').nth(2).locator('.display-transport')).toContainText('kein stiller Qualitätswechsel');
  await expect(page.locator('.display-camera').nth(3).locator('.display-transport')).toContainText('hls · HLS');
  const boxes = await page.locator('.display-camera').evaluateAll(nodes => nodes.map(node => {
    const box = node.getBoundingClientRect();
    return {width: Math.round(box.width), height: Math.round(box.height)};
  }));
  expect(new Set(boxes.map(box => box.width)).size).toBe(1);
  expect(new Set(boxes.map(box => box.height)).size).toBe(1);
});

test('gekoppeltes Display zeigt Blink nur passiv und fordert keinen Live-Lease an', async ({page}) => {
  const mock = await mockDisplayApi(page, {
    paired: true,
    device: {id: 'display-1', name: 'Leitstellen-TV'},
    timezone: 'Europe/Berlin',
    active: true,
    profile: {id: 'profile-1', name: 'Einfahrt'},
    nextProfileStart: null,
    nextProfileName: null
  }, [{
    id: 'blink-1',
    name: 'Blink Einfahrt',
    source: 'Blink Cloud · bei Bedarf',
    enabled: true,
    externalSource: true,
    onDemand: true,
    displayMode: 'explicit',
    explicitLiveOnly: true,
    lowPath: 'blink-1-low',
    highPath: 'blink-1-low',
    snapshotPath: '/blink-thumbnail.jpg',
    streamMode: 'auto',
    features: {audio: false, ptz: false, ptzAxes: [], clips: true}
  }]);
  await page.route('**/blink-thumbnail.jpg*', route => route.fulfill({
    status: 200,
    contentType: 'image/jpeg',
    body: Buffer.from('/9j/2Q==', 'base64')
  }));
  await page.goto('/display.html');
  await expect(page.locator('.display-camera')).toHaveCount(1);
  await expect(page.locator('.display-camera img')).toBeVisible();
  await page.waitForTimeout(250);
  expect(mock.leaseRequests()).toBe(0);
});
