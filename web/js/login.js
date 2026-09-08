// Sign-in and sign-up. Deliberately separate from the dashboard bundle: this
// page must render and work before there is any session to load.

const $ = (id) => document.getElementById(id);

const loginForm = $('login-form');
const signupForm = $('signup-form');
const errorBox = $('error');
const errorText = $('error-text');

function showError(message) {
  errorText.textContent = message;
  errorBox.classList.add('show');
}

function clearError() {
  errorBox.classList.remove('show');
}

function swap(to) {
  clearError();
  const signup = to === 'signup';
  loginForm.hidden = signup;
  signupForm.hidden = !signup;
  location.hash = signup ? '#signup' : '';
  (signup ? $('signup-name') : $('login-email')).focus();
}

$('to-signup').addEventListener('click', () => swap('signup'));
$('to-login').addEventListener('click', (e) => {
  e.preventDefault();
  swap('login');
});

async function submit(path, body, button, busyLabel) {
  clearError();
  const label = button.textContent;
  button.disabled = true;
  button.textContent = busyLabel;
  try {
    const res = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      showError(data.message || data.error || 'That did not work. Please try again.');
      return;
    }
    location.href = '/';
  } catch {
    showError('Could not reach the server. Check that it is running and try again.');
  } finally {
    button.disabled = false;
    button.textContent = label;
  }
}

loginForm.addEventListener('submit', (e) => {
  e.preventDefault();
  submit('/api/auth/login', { email: $('login-email').value.trim(), password: $('login-password').value }, $('login-submit'), 'Signing in…');
});

signupForm.addEventListener('submit', (e) => {
  e.preventDefault();
  submit(
    '/api/auth/signup',
    { name: $('signup-name').value.trim(), email: $('signup-email').value.trim(), password: $('signup-password').value },
    $('signup-submit'),
    'Creating…'
  );
});

// Already signed in? Skip straight through rather than showing a form that will
// immediately redirect after a pointless round trip.
fetch('/api/auth/me', { credentials: 'same-origin' })
  .then((r) => (r.ok ? r.json() : null))
  .then((data) => {
    if (data?.user) location.href = '/';
    else if (data && data.allowSignup === false) $('to-signup').hidden = true;
  })
  .catch(() => {});

if (location.hash === '#signup') swap('signup');
