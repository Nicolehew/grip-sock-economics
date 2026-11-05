// Username + password gate for the whole site (Vercel Routing Middleware).
// Set APP_USERNAME and APP_PASSWORD in Vercel → Project → Settings → Environment Variables.
// Until both are set, the site stays open, exactly as before.

export const config = { matcher: '/((?!favicon.ico).*)' };

const COOKIE = 'gs_auth';
const MAX_AGE = 60 * 60 * 24 * 30; // stay logged in for 30 days
const enc = new TextEncoder();

// Tells Vercel to carry on and serve the page as normal.
const next = () => new Response(null, { headers: { 'x-middleware-next': '1' } });
const redirect = (to, cookie) => {
  const h = new Headers({ Location: to });
  if (cookie) h.append('Set-Cookie', cookie);
  return new Response(null, { status: 303, headers: h });
};

async function sign(user, pass, exp) {
  const key = await crypto.subtle.importKey('raw', enc.encode(pass + '|' + user), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(user + '|' + exp));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function sameText(a, b) {
  // compare without stopping early, so timing gives nothing away
  const x = enc.encode(String(a)), y = enc.encode(String(b));
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}
async function loggedIn(request, user, pass) {
  const m = (request.headers.get('cookie') || '').match(new RegExp('(?:^|;\\s*)' + COOKIE + '=([^;]+)'));
  if (!m) return false;
  const [exp, sig] = decodeURIComponent(m[1]).split('.');
  if (!exp || !sig || Number(exp) < Date.now() / 1000) return false;
  return sameText(sig, await sign(user, pass, exp));
}

export default async function middleware(request) {
  const user = process.env.APP_USERNAME, pass = process.env.APP_PASSWORD;
  if (!user || !pass) return next(); // login not switched on yet

  const url = new URL(request.url);
  const path = url.pathname.replace(/\.html$/, '');

  if (path === '/logout') return redirect('/login?out=1', `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);

  if (path === '/login') {
    if (request.method === 'POST') {
      const form = await request.formData();
      const okUser = sameText(form.get('username') || '', user);
      const okPass = sameText(form.get('password') || '', pass);
      if (okUser && okPass) {
        const exp = Math.floor(Date.now() / 1000) + MAX_AGE;
        const cookie = `${COOKIE}=${exp}.${await sign(user, pass, exp)}; Path=/; Max-Age=${MAX_AGE}; HttpOnly; Secure; SameSite=Lax`;
        return redirect('/', cookie);
      }
      await new Promise(r => setTimeout(r, 800)); // slow down guessing
      return redirect('/login?error=1');
    }
    if (await loggedIn(request, user, pass)) return redirect('/');
    return next(); // show the login page
  }

  if (await loggedIn(request, user, pass)) return next();
  return redirect('/login');
}
