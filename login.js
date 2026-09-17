const form = document.getElementById('login');
const status = document.getElementById('status');
const logout = document.getElementById('logout');
const submit = document.getElementById('submit');

function signedIn() {
  status.textContent = 'Signed in. Return to Watch-Dawg to run your audit.';
  form.hidden = true;
  logout.hidden = false;
}

fetch('/auth/session', { credentials: 'same-origin', cache: 'no-store' })
  .then(response => { if (response.ok) signedIn(); })
  .catch(() => { status.textContent = 'Unable to check sign-in status.'; });

form.addEventListener('submit', async event => {
  event.preventDefault();
  submit.disabled = true;
  status.textContent = 'Signing in…';
  try {
    const response = await fetch('/auth/login', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: form.username.value, password: form.password.value }),
    });
    form.password.value = '';
    const result = await response.json();
    if (response.ok) signedIn();
    else status.textContent = result.detail || 'Sign-in failed.';
  } catch { status.textContent = 'Sign-in is unavailable. Please try again.'; }
  finally { form.password.value = ''; submit.disabled = false; }
});

logout.addEventListener('click', async () => {
  logout.disabled = true;
  try {
    const response = await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin' });
    if (!response.ok) throw new Error('Sign-out rejected');
    status.textContent = 'Signed out.';
    form.hidden = false;
    logout.hidden = true;
  } catch { status.textContent = 'Sign-out failed. Please retry.'; }
  finally { logout.disabled = false; }
});
