/**
 * Escape the given string for safe use in a regular expression.
 * @param {string} str Original string.
 * @returns {string} Escaped string.
 * @see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions#escaping
 */
const escapeRegExp = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Handle the `auth` method, which is the first request in the authorization flow.
 * @param {Request} request HTTP request.
 * @param {{ [key: string]: string }} env Environment variables.
 * @returns {Promise<Response>} HTTP response.
 */
const handleAuth = async (request, env) => {
  const { url } = request;
  const { searchParams } = new URL(url);
  const provider = searchParams.get('provider');
  const domain = searchParams.get('site_id');
  const { ALLOWED_DOMAINS, GITHUB_CLIENT_ID, GITHUB_HOSTNAME = 'github.com' } = env;

  // Check if the domain is whitelisted
  if (
    ALLOWED_DOMAINS &&
    !ALLOWED_DOMAINS.split(/,/).some((str) =>
      // Escape the input, then replace a wildcard for regex
      domain.match(new RegExp(`^${escapeRegExp(str.trim()).replace('\\*', '.+')}$`)),
    )
  ) {
    return new Response('', { status: 403 });
  }

  // Generate a random string for CSRF protection
  const csrfToken = globalThis.crypto.randomUUID().replaceAll('-', '');
  // Cookie expires in 10 minutes; Use `SameSite=Lax` to make sure the cookie is sent after redirect
  const cookie = `csrf-token=${csrfToken}; HttpOnly; Max-Age=600; SameSite=Lax; Secure`;

  // GitHub
  if (provider === 'github' && GITHUB_CLIENT_ID) {
    const params = new URLSearchParams({
      client_id: GITHUB_CLIENT_ID,
      scope: 'repo,user',
      state: csrfToken,
    });

    return new Response('', {
      status: 302,
      headers: {
        'Set-Cookie': cookie,
        Location: `https://${GITHUB_HOSTNAME}/login/oauth/authorize?${params.toString()}`,
      },
    });
  }

  return new Response('', { status: 403 });
};

/**
 * Handle the `callback` method, which is the second request in the authorization flow.
 * @param {Request} request HTTP request.
 * @param {{ [key: string]: string }} env Environment variables.
 * @returns {Promise<Response>} HTTP response.
 */
const handleCallback = async (request, env) => {
  const { url, headers } = request;
  const { searchParams } = new URL(url);
  const code = searchParams.get('code');
  const csrfToken = searchParams.get('state');
  const csrfTokenCookie = headers.get('Cookie');

  if (!code || !csrfToken || !csrfTokenCookie || csrfTokenCookie !== `csrf-token=${csrfToken}`) {
    return new Response('', { status: 403 });
  }

  const { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_HOSTNAME = 'github.com' } = env;
  let provider;
  let token;
  let error;

  // GitHub
  if (GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET) {
    provider = 'github';

    try {
      const response = await fetch(`https://${GITHUB_HOSTNAME}/login/oauth/access_token`, {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          client_id: GITHUB_CLIENT_ID,
          client_secret: GITHUB_CLIENT_SECRET,
          code,
        }),
      });

      ({ access_token: token, error } = await response.json());
    } catch ({ message }) {
      error = message;
    }
  }

  if (!provider || !(token || error)) {
    return new Response('', { status: 403 });
  }

  const state = error ? 'error' : 'success';
  const content = error ? { error } : { provider, token };

  return new Response(
    `
      <!doctype html><html><body><script>
        (() => {
          window.addEventListener('message', ({ data, origin }) => {
            if (data !== 'authorizing:${provider}') return;
            window.opener.postMessage(
              'authorization:${provider}:${state}:${JSON.stringify(content)}',
              origin
            );
          });
          window.opener.postMessage('authorizing:${provider}', '*');
        })();
      </script></body></html>
    `,
    {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
      },
    },
  );
};

export default {
  /**
   * The main request handler.
   * @param {Request} request HTTP request.
   * @param {{ [key: string]: string }} env Environment variables.
   * @returns {Promise<Response>} HTTP response.
   * @see https://developers.cloudflare.com/workers/runtime-apis/fetch/
   * @see https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
   */
  async fetch(request, env) {
    const { method, url } = request;
    const { pathname } = new URL(url);

    if (method === 'GET' && pathname === '/auth') {
      return handleAuth(request, env);
    }

    if (method === 'GET' && pathname === '/callback') {
      return handleCallback(request, env);
    }

    return new Response('', { status: 404 });
  },
};
