/** Browser session state contains a CSRF nonce, never the backend bearer credential. */
export function createOwnerClient(onChange, request = (...args) => fetch(...args), { authTimeoutMs = 10_000 } = {}) {
  let state = { enabled: false, authenticated: false, unavailable: false, sessionVersion: 0 };
  let csrf = '';
  let operation = 0;
  let query = 0;
  let mutation = null;
  let blocked = false;
  let expiryTimer;
  const audits = new Set();

  function cancelAudits() {
    for (const controller of audits) controller.abort();
    audits.clear();
  }
  function publish(data, forceChange = false) {
    clearTimeout(expiryTimer);
    const nextCsrf = data.authenticated && typeof data.csrf === 'string' ? data.csrf : '';
    const authenticated = data.authenticated === true && !!nextCsrf
      && Number.isFinite(data.expiresAt) && data.expiresAt > Date.now();
    const changed = forceChange || csrf !== nextCsrf || state.authenticated !== authenticated;
    if (changed) cancelAudits();
    csrf = authenticated ? nextCsrf : '';
    state = { enabled: data.enabled === true, authenticated,
      owner: typeof data.owner === 'string' ? data.owner : '', unavailable: data.unavailable === true,
      signingOut: data.signingOut === true, signoutUnconfirmed: data.signoutUnconfirmed === true,
      sessionVersion: state.sessionVersion + Number(changed) };
    if (authenticated) {
      expiryTimer = setTimeout(() => {
        blocked = true;
        operation++;
        query++;
        publish({ enabled: true, authenticated: false, expired: true }, true);
      }, Math.min(data.expiresAt - Date.now(), 2 ** 31 - 1));
      expiryTimer.unref?.();
    }
    onChange({ ...state });
  }
  async function call(path, options = {}) {
    const controller = new AbortController();
    let timer;
    let response;
    let data;
    try {
      [response, data] = await Promise.race([
        (async () => {
          const result = await request(path, { credentials: 'same-origin', cache: 'no-store',
            ...options, signal: controller.signal });
          return [result, await result.json()];
        })(),
        new Promise((_resolve, reject) => {
          timer = setTimeout(() => {
            reject(new Error('Owner sign-in timed out. Please retry.'));
            controller.abort();
          }, authTimeoutMs);
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
    if (!response.ok) {
      const error = new Error(response.status === 429 ? 'Sign-in is temporarily limited. Please wait and try again.'
        : response.status === 401 ? 'Sign-in details were not accepted.' : 'Owner sign-in could not be completed.');
      error.status = response.status;
      throw error;
    }
    return data;
  }
  async function refresh() {
    if (blocked) return state;
    if (mutation) await mutation.catch(() => {});
    if (blocked) return state;
    const current = operation;
    const currentQuery = ++query;
    try {
      const data = await call('/auth/session');
      if (!blocked && current === operation && currentQuery === query) publish(data);
      return state;
    } catch (error) {
      if (!blocked && current === operation && currentQuery === query) {
        publish({ enabled: false, authenticated: false, unavailable: true });
      }
      throw error;
    }
  }
  async function login(username, password) {
    const previous = mutation;
    const current = ++operation;
    query++;
    blocked = false;
    publish({ enabled: true, authenticated: false }, true);
    const pending = (async () => {
      if (previous) await previous.catch(() => {});
      return call('/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username, password }) });
    })();
    mutation = pending;
    try {
      const data = await pending;
      if (current === operation && !blocked) publish(data);
    } finally {
      if (mutation === pending) mutation = null;
    }
  }
  async function logout() {
    const previous = mutation;
    const current = ++operation;
    query++;
    blocked = true;
    publish({ enabled: true, authenticated: false, signingOut: true }, true);
    const pending = (async () => {
      // A pending login can still set the browser cookie. Revoke it after that response arrives.
      if (previous) await previous.catch(() => {});
      // Obtain the current cookie's CSRF nonce without restoring authenticated UI.
      const session = await call('/auth/session');
      if (session.authenticated) {
        await call('/auth/logout', { method: 'POST', headers: { 'x-csrf-token': session.csrf } });
      }
    })();
    mutation = pending;
    try {
      await pending;
      if (current === operation) publish({ enabled: true, authenticated: false });
    } catch (error) {
      if (current === operation) publish({ enabled: true, authenticated: false, signoutUnconfirmed: true });
      throw error;
    } finally {
      if (mutation === pending) mutation = null;
    }
  }
  async function audit(body, signal, onDelta) {
    const started = operation;
    await refresh();
    if (started !== operation || signal?.aborted) throw new DOMException('Request superseded', 'AbortError');
    if (!state.enabled || !state.authenticated) {
      const error = new Error(state.enabled ? 'Sign in as the configured owner to request AI insights.'
        : 'AI owner sign-in is not configured on this host.');
      error.ownerRequired = true;
      throw error;
    }
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal?.addEventListener('abort', abort, { once: true });
    audits.add(controller);
    try {
      const response = await request('/api/ai/audit', { method: 'POST', credentials: 'same-origin',
        headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
        body: JSON.stringify(body), signal: controller.signal });
      if (controller.signal.aborted || operation !== started) {
        await response.body?.cancel().catch(() => {});
        throw new DOMException('Request superseded', 'AbortError');
      }
      if (response.status === 401) {
        if (response.headers.get('www-authenticate')?.toLowerCase().startsWith('bearer')) {
          throw new Error('AI backend authorization is unavailable');
        }
        blocked = true;
        operation++;
        publish({ enabled: true, authenticated: false }, true);
        const error = new Error('Your owner session expired. Sign in again to request AI insights.');
        error.ownerRequired = true;
        throw error;
      }
      await readAiStream(response, chunk => {
        if (!controller.signal.aborted && operation === started) onDelta(chunk);
      });
      if (controller.signal.aborted || operation !== started) throw new DOMException('Request superseded', 'AbortError');
    } finally {
      signal?.removeEventListener('abort', abort);
      audits.delete(controller);
    }
  }
  return Object.freeze({ refresh, login, logout, audit });
}

/** EOF is successful only after an explicit complete SSE frame from the backend. */
export async function readAiStream(response, onDelta) {
  if (!response.ok || !response.body) throw new Error('AI service unavailable');
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let complete = false;
  let bytes = 0;
  function consume() {
    let boundary;
    while ((boundary = /\r?\n\r?\n/.exec(buffer))) {
      const event = buffer.slice(0, boundary.index);
      buffer = buffer.slice(boundary.index + boundary[0].length);
      const data = event.split(/\r?\n/).filter(line => line.startsWith('data:'))
        .map(line => line.slice(5).replace(/^ /, '')).join('\n');
      if (!data) continue;
      if (complete) throw new Error('AI stream continued after completion');
      const message = JSON.parse(data);
      if (message.error) throw new Error('AI service reported an error');
      if (typeof message.delta === 'string') onDelta(message.delta);
      if (message.done === true) complete = true;
    }
  }
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      bytes += value.length;
      if (bytes > 2 * 1024 * 1024) throw new Error('AI response exceeded the limit');
      buffer += decoder.decode(value, { stream: true });
      consume();
    }
    buffer += decoder.decode();
    consume();
    if (buffer.trim() || !complete) throw new Error('AI response ended before completion');
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
}
