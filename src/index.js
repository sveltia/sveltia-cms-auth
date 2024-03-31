/**
 * Escape the given string for safe use in a regular expression.
 * @param {string} str - Original string.
 * @returns {string} Escaped string.
 * @see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions#escaping
 */
const escapeRegExp = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Handle the `auth` method, which is the first request in the authorization flow.
 * @param {Request} request - HTTP request.
 * @param {{ [key: string]: string }} env - Environment variables.
 * @returns {Promise<Response>} HTTP response.
 */
const handleAuth = async (request, env) => {
  const { url } = request;
  const { origin, searchParams } = new URL(url);
  const provider = searchParams.get('provider');
  const domain = searchParams.get('site_id');

  const {
    ALLOWED_DOMAINS,
    GITHUB_CLIENT_ID,
    GITHUB_HOSTNAME = 'github.com',
    GITLAB_CLIENT_ID,
    GITLAB_HOSTNAME = 'gitlab.com',
  } = env;

  // Check if the domain is whitelisted
  if (
    domain &&
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
  let authURL = '';

  // GitHub
  if (provider === 'github' && GITHUB_CLIENT_ID) {
    const params = new URLSearchParams({
      client_id: GITHUB_CLIENT_ID,
      scope: 'repo,user',
      state: csrfToken,
    });

    authURL = `https://${GITHUB_HOSTNAME}/login/oauth/authorize?${params.toString()}`;
  }

  // GitLab
  if (provider === 'gitlab' && GITLAB_CLIENT_ID) {
    const params = new URLSearchParams({
      client_id: GITLAB_CLIENT_ID,
      redirect_uri: `${origin}/callback`,
      response_type: 'code',
      scope: 'api',
      state: csrfToken,
    });

    authURL = `https://${GITLAB_HOSTNAME}/oauth/authorize?${params.toString()}`;
  }

  if (authURL) {
    return new Response('', {
      status: 302,
      headers: {
        Location: authURL,
        // Cookie expires in 10 minutes; Use `SameSite=Lax` to make sure the cookie is sent by the
        // browser after redirect
        'Set-Cookie': `csrf-token=${csrfToken}; HttpOnly; Max-Age=600; SameSite=Lax; Secure`,
      },
    });
  }

  return new Response('', { status: 403 });
};

/**
 * Handle the `callback` method, which is the second request in the authorization flow.
 * @param {Request} request - HTTP request.
 * @param {{ [key: string]: string }} env - Environment variables.
 * @returns {Promise<Response>} HTTP response.
 */
const handleCallback = async (request, env) => {
  const { url, headers } = request;
  const { origin, searchParams } = new URL(url);
  const code = searchParams.get('code');
  const csrfToken = searchParams.get('state');
  const csrfTokenCookie = headers.get('Cookie');

  if (!code || !csrfToken || !csrfTokenCookie || csrfTokenCookie !== `csrf-token=${csrfToken}`) {
    return new Response('', { status: 403 });
  }

  const {
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    GITHUB_HOSTNAME = 'github.com',
    GITLAB_CLIENT_ID,
    GITLAB_CLIENT_SECRET,
    GITLAB_HOSTNAME = 'gitlab.com',
  } = env;

  let provider = '';
  let tokenURL = '';
  let requestBody = {};

  // GitHub
  if (GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET) {
    provider = 'github';
    tokenURL = `https://${GITHUB_HOSTNAME}/login/oauth/access_token`;
    requestBody = {
      code,
      client_id: GITHUB_CLIENT_ID,
      client_secret: GITHUB_CLIENT_SECRET,
    };
  }

  // GitLab
  if (GITLAB_CLIENT_ID && GITLAB_CLIENT_SECRET) {
    provider = 'gitlab';
    tokenURL = `https://${GITLAB_HOSTNAME}/oauth/token`;
    requestBody = {
      code,
      client_id: GITLAB_CLIENT_ID,
      client_secret: GITLAB_CLIENT_SECRET,
      grant_type: 'authorization_code',
      redirect_uri: `${origin}/callback`,
    };
  }

  if (!provider) {
    return new Response('', { status: 403 });
  }

  let token = '';
  let error = '';

  try {
    const response = await fetch(tokenURL, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
    });

    const { ok, status } = response;

    if (!ok) {
      throw new Error(`Server responded with status ${status}`);
    }

    ({ access_token: token, error } = await response.json());
  } catch (/** @type {any} */ { message }) {
    error = message;
  }

  if (!(token || error)) {
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
   * @param {Request} request - HTTP request.
   * @param {{ [key: string]: string }} env - Environment variables.
   * @returns {Promise<Response>} HTTP response.
   * @see https://developers.cloudflare.com/workers/runtime-apis/fetch/
   * @see https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
   * @see https://docs.gitlab.com/ee/api/oauth2.html#authorization-code-flow
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
