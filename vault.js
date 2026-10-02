/* Password-derived AES-GCM decryption. No plaintext assets, password, or key is published. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const encoder = new TextEncoder(), decoder = new TextDecoder();
  const blobURLs = [];
  let encryptedBundle;
  function fromBase64(value) { return Uint8Array.from(atob(value), c => c.charCodeAt(0)); }
  function blob(data, type) { const url = URL.createObjectURL(new Blob([data], { type })); blobURLs.push(url); return url; }
  function release() { while (blobURLs.length) URL.revokeObjectURL(blobURLs.pop()); }
  async function loadBundle() {
    if (encryptedBundle) return encryptedBundle;
    $('status').textContent = '正在加载加密照片，首次访问请稍候…';
    const [configResponse, contentResponse] = await Promise.all([
      fetch('vault-config.json', { cache: 'no-store' }),
      fetch('content.enc', { cache: 'no-store' })
    ]);
    if (!configResponse.ok || !contentResponse.ok) throw new Error('NETWORK');
    const config = await configResponse.json();
    if (config.version !== 1 || config.iterations !== 600000 || config.cipher !== 'AES-256-GCM' || config.kdf !== 'PBKDF2-SHA256') throw new Error('FORMAT');
    const ciphertext = await contentResponse.arrayBuffer();
    if (ciphertext.byteLength !== config.bytes) throw new Error('NETWORK');
    encryptedBundle = { config, ciphertext };
    return encryptedBundle;
  }
  function mount(plaintext) {
    const data = new Uint8Array(plaintext);
    const manifestLength = new DataView(plaintext).getUint32(0);
    if (manifestLength > 100000 || manifestLength + 4 > data.length) throw new Error('FORMAT');
    const manifest = JSON.parse(decoder.decode(data.subarray(4, 4 + manifestLength)));
    if (manifest.version !== 1 || !Array.isArray(manifest.files)) throw new Error('FORMAT');
    const files = new Map(), urls = new Map(), base = 4 + manifestLength;
    for (const entry of manifest.files) {
      if (entry.offset < 0 || entry.length < 0 || base + entry.offset + entry.length > data.length) throw new Error('FORMAT');
      const content = data.subarray(base + entry.offset, base + entry.offset + entry.length);
      files.set(entry.path, content);
      if (entry.path !== 'index.html' && entry.path !== 'assets/people-data.js') urls.set(entry.path, blob(content, entry.mime));
    }
    const rosterSource = decoder.decode(files.get('assets/people-data.js'));
    const roster = JSON.parse(rosterSource.slice(rosterSource.indexOf('=') + 1).trim().replace(/;$/, ''));
    for (const region of roster) for (const person of region.people) person.photo = urls.get(person.photo) || 'data:,';
    urls.set('assets/people-data.js', blob('window.PEOPLE_REGIONS = ' + JSON.stringify(roster) + ';', 'text/javascript'));
    const doc = new DOMParser().parseFromString(decoder.decode(files.get('index.html')), 'text/html');
    for (const script of doc.querySelectorAll('script[src]')) {
      const url = urls.get(script.getAttribute('src'));
      if (!url) throw new Error('FORMAT');
      script.setAttribute('src', url);
    }
    for (const style of doc.querySelectorAll('link[rel="stylesheet"]')) {
      const url = urls.get(style.getAttribute('href'));
      if (!url) throw new Error('FORMAT');
      style.setAttribute('href', url);
    }
    const lock = doc.createElement('button'); lock.id = 'lock-site'; lock.className = 'quiet-button vault-lock'; lock.type = 'button'; lock.textContent = '退出'; lock.title = '退出并重新锁定';
    doc.querySelector('.top-actions').prepend(lock);
    const smallScreen = doc.createElement('style');
    smallScreen.textContent = '@media(max-width:480px){.top-actions{gap:8px}.quiet-button.vault-lock{font-size:11px}.brand{gap:8px;letter-spacing:1px}.brand small{font-size:7px}}';
    doc.head.append(smallScreen);
    doc.querySelector('.brand').setAttribute('href', '#');
    const note = doc.querySelector('#about-dialog p:last-of-type');
    if (note) note.textContent = '此页面由访问密码在浏览器本地解密。请勿转发密码或未经允许分享亲友照片。点击顶部“退出”可重新锁定页面。';
    const frame = document.createElement('iframe'); frame.id = 'wedding-frame'; frame.title = '婚礼祝福地图';
    frame.addEventListener('load', () => {
      const inner = frame.contentDocument;
      inner.getElementById('lock-site')?.addEventListener('click', () => location.reload());
      inner.querySelector('.brand')?.addEventListener('click', event => { event.preventDefault(); inner.getElementById('reset')?.click(); });
    });
    frame.srcdoc = '<!doctype html>\n' + doc.documentElement.outerHTML;
    document.title = doc.title;
    document.body.append(frame);
    $('gate').hidden = true;
    $('password').value = '';
    $('status').textContent = '';
  }
  $('toggle-password').addEventListener('click', () => {
    const show = $('password').type === 'password';
    $('password').type = show ? 'text' : 'password';
    $('toggle-password').textContent = show ? '隐藏' : '显示';
    $('toggle-password').setAttribute('aria-label', show ? '隐藏密码' : '显示密码');
  });
  $('unlock-form').addEventListener('submit', async event => {
    event.preventDefault();
    if (!window.crypto?.subtle) { $('status').textContent = '请通过 HTTPS 网址在 Safari、Chrome 或 Edge 中打开。'; return; }
    const password = $('password').value.trim();
    if (!password) return;
    $('unlock-button').disabled = true;
    try {
      const { config, ciphertext } = await loadBundle();
      $('status').textContent = '正在解锁祝福地图…';
      const salt = fromBase64(config.salt), iv = fromBase64(config.iv);
      if (salt.length !== 16 || iv.length !== 12) throw new Error('FORMAT');
      const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
      const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: config.iterations }, material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
      const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode('wedding-blessings-v1'), tagLength: 128 }, key, ciphertext);
      mount(plaintext);
    } catch (error) {
      release();
      if (error.name === 'OperationError') $('status').textContent = '访问密码不正确，请检查后重试。';
      else if (error.message === 'FORMAT') $('status').textContent = '页面版本不匹配，请刷新后重试。';
      else $('status').textContent = '暂时无法打开，请检查网络并刷新重试。';
    } finally { $('unlock-button').disabled = false; }
  });
  window.addEventListener('pagehide', release);
})();
