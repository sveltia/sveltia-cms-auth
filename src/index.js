/**
 * Backend name of the only supported Git service. Sveltia CMS sends it as the `provider` parameter
 * and expects it in the messages posted by the authorization popup.
 */
const PROVIDER = 'github';
/**
 * Pattern of the cookie that holds the CSRF token during the authorization flow.
 */
const CSRF_COOKIE_PATTERN = new RegExp(`\\bcsrf-token=${PROVIDER}_([0-9a-f]{32})\\b`);

/**
 * OAuth scopes: the scope to request when the client doesn’t ask for one, and the scopes that may
 * be requested.
 *
 * Scopes only apply to an OAuth app. A GitHub App ignores the `scope` parameter, and its token is
 * limited to the permissions configured for the app and the repositories it’s installed on, so this
 * is kept for deployments that still use an OAuth app.
 *
 * A client can ask for a narrower scope than the default — Sveltia CMS does this with its
 * `auth_scope` backend option, so a public repository doesn’t require access to a contributor’s
 * private ones — but only from this list. The endpoint is reachable by anyone, and a token minted
 * with a wider scope than the CMS needs keeps that scope for every later sign-in, so the request is
 * not taken on trust. Anything unrecognized falls back to the default, which is what an older
 * version of this worker granted regardless, so an unfamiliar client still signs in.
 *
 * GitHub’s `workflow` scope is wider than the default, so it’s only allowed when the
 * `GITHUB_ALLOW_WORKFLOW_SCOPE` environment variable is `true`: see {@link getScope}.
 * @see https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps
 */
const GITHUB_SCOPES = {
  default: 'repo,user',
  allowed: ['repo', 'public_repo', 'user', 'read:user', 'user:email'],
};

/**
 * Work out the OAuth scope to request from GitHub.
 * @param {string | undefined} requested - The `scope` parameter from the request, if any. Scopes
 * may be separated by commas or spaces.
 * @param {{ [key: string]: string }} env - Environment variables.
 * @returns {string} Scope to request.
 */
const getScope = (requested, env) => {
  const { default: fallback, allowed } = GITHUB_SCOPES;
  let scopes = (requested ?? '').split(/[\s,]+/).filter(Boolean);
  const allowWorkflow = env.GITHUB_ALLOW_WORKFLOW_SCOPE === 'true';

  // The `workflow` scope lets a token change GitHub Actions workflows in every repository the user
  // can push to, so it takes the operator’s consent as well as the site’s. Without it, the scope is
  // left out rather than the request falling back to the default, which could be wider than what
  // was asked for, e.g. `repo` instead of `public_repo`
  if (!allowWorkflow && scopes.includes('workflow')) {
    // eslint-disable-next-line no-console
    console.warn(
      'Ignoring the "workflow" scope. With an OAuth app, set ' +
        'GITHUB_ALLOW_WORKFLOW_SCOPE to "true" to allow it. A GitHub App ignores scopes; grant ' +
        'the Workflows permission instead.',
    );

    scopes = scopes.filter((scope) => scope !== 'workflow');
  }

  if (!scopes.length) {
    return fallback;
  }

  if (scopes.every((scope) => allowed.includes(scope) || (allowWorkflow && scope === 'workflow'))) {
    return scopes.join(',');
  }

  // The default is wider than what was asked for, so a client that meant to narrow the scope
  // silently doesn’t. Leave a trace for whoever is running the worker
  // eslint-disable-next-line no-console
  console.warn(`Ignoring the unsupported "${requested}" scope; requesting "${fallback}".`);

  return fallback;
};

/**
 * Escape the given string for safe use in a regular expression.
 * @param {string} str - Original string.
 * @returns {string} Escaped string.
 * @see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions#escaping
 */
const escapeRegExp = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Convert the `ALLOWED_DOMAINS` environment variable into a list of anchored regular expression
 * sources. The sources are used both here and in the client-side script embedded in
 * {@link outputHTML}, so a hostname is matched by the exact same rules on either side.
 * @param {string} [allowedDomains] - Comma-separated list of hostnames, which may contain a
 * wildcard (`*`).
 * @returns {string[]} Regular expression sources. Empty if the variable is not configured.
 */
const getDomainPatterns = (allowedDomains) =>
  (allowedDomains ?? '')
    .split(/,/)
    .map((str) => str.trim())
    .filter(Boolean)
    // Escape the input, then replace a wildcard for regex
    .map((str) => `^${escapeRegExp(str).replaceAll('\\*', '.+')}$`);

/**
 * Check whether the given hostname matches any of the allowed domain patterns.
 * @param {string} hostname - Hostname to check.
 * @param {string[]} patterns - Regular expression sources from {@link getDomainPatterns}.
 * @returns {boolean} Result.
 */
const isAllowedHostname = (hostname, patterns) =>
  patterns.some((pattern) => new RegExp(pattern).test(hostname));

/**
 * Serialize the given value for safe embedding in an inline `<script>` block.
 * @param {string | boolean | string[]} value - Value to be serialized.
 * @returns {string} JavaScript literal.
 */
const serialize = (value) => JSON.stringify(value ?? null).replaceAll('<', '\\u003c');

/**
 * Output HTML response that communicates with the window opener.
 * @param {object} args - Options.
 * @param {string} [args.provider] - Backend name. Sveltia CMS only accepts the message if it
 * matches the backend the site uses.
 * @param {string} [args.token] - OAuth token.
 * @param {string} [args.refreshToken] - OAuth refresh token. Only issued by a GitHub App with user
 * access token expiration enabled.
 * @param {string} [args.error] - Error message when an OAuth token is not available.
 * @param {string} [args.errorCode] - Error code to be used to localize the error message in
 * Sveltia CMS.
 * @param {{ [key: string]: string }} [args.env] - Environment variables.
 * @returns {Response} Response with HTML.
 */
const outputHTML = ({ provider = PROVIDER, token, refreshToken, error, errorCode, env = {} }) => {
  const state = error ? 'error' : 'success';
  const content = error ? { provider, error, errorCode } : { provider, token, refreshToken };
  const handshake = `authorizing:${provider}`;
  const message = `authorization:${provider}:${state}:${JSON.stringify(content)}`;

  return new Response(
    `
      <!doctype html><html><body><script>
        (() => {
          const trustedPatterns = ${serialize(getDomainPatterns(env.ALLOWED_DOMAINS))};
          const hasToken = ${serialize(!!token)};
          const handshake = ${serialize(handshake)};
          const message = ${serialize(message)};

          const isTrusted = (origin) => {
            try {
              const { hostname } = new URL(origin);

              return trustedPatterns.some((pattern) => new RegExp(pattern).test(hostname));
            } catch {
              return false;
            }
          };

          window.addEventListener('message', ({ data, origin }) => {
            if (data !== handshake) {
              return;
            }

            // Unlike the site_id parameter, which the caller supplies, the origin of a message
            // event is set by the browser and cannot be forged by the sender, so it’s the only
            // reliable indication of who opened this popup. An error carries no secret, so it’s
            // always passed through to keep the sign-in screen informative
            if (hasToken && trustedPatterns.length && !isTrusted(origin)) {
              return;
            }

            window.opener?.postMessage(message, origin);
          });
          window.opener?.postMessage(handshake, '*');
        })();
      </script></body></html>
    `,
    {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        // The page may contain an access token and a long-lived refresh token
        'Cache-Control': 'no-store',
        // Delete CSRF token
        'Set-Cookie': `csrf-token=deleted; HttpOnly; Max-Age=0; Path=/; SameSite=Lax; Secure`,
      },
    },
  );
};

/**
 * Error messages shown on the sign-in screen, keyed by the error code that Sveltia CMS uses to
 * localize them.
 */
const errorMessages = {
  UNSUPPORTED_BACKEND: 'Your Git backend is not supported by the authenticator.',
  UNSUPPORTED_DOMAIN: 'Your domain is not allowed to use the authenticator.',
  MISCONFIGURED_CLIENT: 'GitHub App client ID or secret is not configured.',
  AUTH_CODE_REQUEST_FAILED: 'Failed to receive an authorization code. Please try again later.',
  CSRF_DETECTED: 'Potential CSRF attack detected. Authentication flow aborted.',
  TOKEN_REQUEST_FAILED: 'Failed to request an access token. Please try again later.',
  MALFORMED_RESPONSE: 'Server responded with malformed data. Please try again later.',
};

/**
 * Output an HTML response that reports the given error to the window opener.
 * @param {keyof typeof errorMessages} errorCode - Error code.
 * @param {{ [key: string]: string }} env - Environment variables.
 * @param {string} [provider] - Backend name, if not `github`.
 * @returns {Response} Response with HTML.
 */
const outputError = (errorCode, env, provider) =>
  outputHTML({ env, provider, error: errorMessages[errorCode], errorCode });

/**
 * Check whether the GitHub App client credentials are configured.
 * @param {{ [key: string]: string }} env - Environment variables.
 * @returns {boolean} Result.
 */
const isClientConfigured = ({ GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET }) =>
  !!GITHUB_CLIENT_ID && !!GITHUB_CLIENT_SECRET;

/**
 * Request an access token from GitHub, adding the client credentials to the given parameters.
 * @param {Record<string, string>} params - Grant parameters, e.g. `code` or `refresh_token` with
 * `grant_type`.
 * @param {{ [key: string]: string }} env - Environment variables.
 * @returns {Promise<Response | undefined>} Response, or `undefined` if the request failed.
 * @see https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens
 */
const requestToken = async (params, env) => {
  const { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_HOSTNAME = 'github.com' } = env;

  try {
    return await fetch(`https://${GITHUB_HOSTNAME}/login/oauth/access_token`, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        ...params,
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
      }),
    });
  } catch {
    return undefined;
  }
};

/**
 * Handle the `auth` method, which is the first request in the authorization flow.
 * @param {Request} request - HTTP request.
 * @param {{ [key: string]: string }} env - Environment variables.
 * @returns {Promise<Response>} HTTP response.
 */
const handleAuth = async (request, env) => {
  const { url } = request;
  const { searchParams } = new URL(url);
  const { provider, site_id: domain, scope: requestedScope } = Object.fromEntries(searchParams);

  if (provider !== PROVIDER) {
    // Echo the backend name, e.g. `gitlab`, so the CMS accepts the message and shows the error
    // instead of waiting forever. Anything unexpected is not echoed
    return outputError(
      'UNSUPPORTED_BACKEND',
      env,
      /^[a-z-]+$/.test(provider ?? '') ? provider : 'unknown',
    );
  }

  const scope = getScope(requestedScope, env);
  const { ALLOWED_DOMAINS, GITHUB_CLIENT_ID, GITHUB_HOSTNAME = 'github.com' } = env;
  const domainPatterns = getDomainPatterns(ALLOWED_DOMAINS);

  // Check if the domain is whitelisted
  if (domainPatterns.length && !isAllowedHostname(domain ?? '', domainPatterns)) {
    return outputError('UNSUPPORTED_DOMAIN', env);
  }

  if (!isClientConfigured(env)) {
    return outputError('MISCONFIGURED_CLIENT', env);
  }

  // Generate a random string for CSRF protection
  const csrfToken = globalThis.crypto.randomUUID().replaceAll('-', '');

  const params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    scope,
    state: csrfToken,
  });

  const authURL = `https://${GITHUB_HOSTNAME}/login/oauth/authorize?${params.toString()}`;

  // Redirect to the authorization server
  return new Response('', {
    status: 302,
    headers: {
      Location: authURL,
      // Cookie expires in 10 minutes; Use `SameSite=Lax` to make sure the cookie is sent by the
      // browser after redirect
      'Set-Cookie':
        `csrf-token=${PROVIDER}_${csrfToken}; ` +
        `HttpOnly; Path=/; Max-Age=600; SameSite=Lax; Secure`,
    },
  });
};

/**
 * Handle the `callback` method, which is the second request in the authorization flow.
 * @param {Request} request - HTTP request.
 * @param {{ [key: string]: string }} env - Environment variables.
 * @returns {Promise<Response>} HTTP response.
 */
const handleCallback = async (request, env) => {
  const { url, headers } = request;
  const { searchParams } = new URL(url);
  const { code, state } = Object.fromEntries(searchParams);
  const [, csrfToken] = headers.get('Cookie')?.match(CSRF_COOKIE_PATTERN) ?? [];

  if (!code || !state) {
    return outputError('AUTH_CODE_REQUEST_FAILED', env);
  }

  if (!csrfToken || state !== csrfToken) {
    return outputError('CSRF_DETECTED', env);
  }

  if (!isClientConfigured(env)) {
    return outputError('MISCONFIGURED_CLIENT', env);
  }

  const response = await requestToken({ code }, env);

  if (!response) {
    return outputError('TOKEN_REQUEST_FAILED', env);
  }

  /** @type {Record<string, string> | undefined} */
  let result;

  try {
    result = await response.json();
  } catch {
    //
  }

  const { access_token: token, refresh_token: refreshToken, error } = result ?? {};

  if (!token && !error) {
    return outputError('MALFORMED_RESPONSE', env);
  }

  return outputHTML({ env, token, refreshToken, error });
};

/**
 * Get the CORS headers for a request to the token endpoint, which Sveltia CMS calls with `fetch`
 * from the site to refresh an expired access token. The request’s origin is echoed back only if
 * it’s allowed by the `ALLOWED_DOMAINS` environment variable, or if the variable is not configured,
 * just like the sign-in flow. Unlike the origin of a message event, the `Origin` header can be
 * forged by a client other than a browser, so this only stops other sites from using the Worker;
 * it’s the refresh token itself that authorizes a refresh, as with any OAuth client.
 * @param {Request} request - HTTP request.
 * @param {{ [key: string]: string }} env - Environment variables.
 * @returns {Record<string, string> | undefined} Headers, or `undefined` if the origin is not
 * allowed.
 */
const getCorsHeaders = (request, env) => {
  const origin = request.headers.get('Origin');

  if (!origin) {
    return undefined;
  }

  const domainPatterns = getDomainPatterns(env.ALLOWED_DOMAINS);
  let hostname = '';

  try {
    ({ hostname } = new URL(origin));
  } catch {
    //
  }

  // An opaque origin (`null`) leaves the hostname empty
  if (!hostname || (domainPatterns.length && !isAllowedHostname(hostname, domainPatterns))) {
    return undefined;
  }

  return {
    'Access-Control-Allow-Origin': origin,
    // Sveltia CMS sends cookies with the request if the `include_credentials` option is enabled
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'POST',
    'Access-Control-Allow-Headers': 'Accept, Content-Type',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
};

/**
 * Output a JSON response for the token endpoint.
 * @param {object} body - Response body.
 * @param {object} [options] - Options.
 * @param {number} [options.status] - HTTP status code.
 * @param {Record<string, string>} [options.headers] - Additional headers, e.g. CORS.
 * @returns {Response} Response.
 */
const outputJSON = (body, { status = 200, headers = {} } = {}) =>
  Response.json(body, { status, headers: { 'Cache-Control': 'no-store', ...headers } });

/**
 * Handle a token refresh request from Sveltia CMS. A GitHub App’s user access token expires after 8
 * hours by default, and refreshing it requires the client secret, so the CMS cannot talk to GitHub
 * directly. The CMS sends the request to the authorization URL with `/authorize` replaced by
 * `/access_token`, which means `/auth` itself with the default `auth_endpoint` option, or
 * `/oauth/access_token` if the option is `oauth/authorize`.
 * @param {Request} request - HTTP request.
 * @param {{ [key: string]: string }} env - Environment variables.
 * @returns {Promise<Response>} HTTP response.
 * @see https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens
 */
const handleRefresh = async (request, env) => {
  const corsHeaders = getCorsHeaders(request, env);

  if (!corsHeaders) {
    return outputJSON({ error: 'unsupported_domain' }, { status: 403 });
  }

  /** @type {Record<string, unknown> | undefined} */
  let params;

  try {
    params = await request.json();
  } catch {
    //
  }

  const refreshToken = params?.refresh_token;

  if (params?.grant_type !== 'refresh_token' || typeof refreshToken !== 'string' || !refreshToken) {
    return outputJSON({ error: 'invalid_request' }, { status: 400, headers: corsHeaders });
  }

  if (!isClientConfigured(env)) {
    return outputJSON({ error: 'misconfigured_client' }, { status: 500, headers: corsHeaders });
  }

  // The `client_id` sent by the CMS is ignored; it’s empty unless the `app_id` option is set
  const response = await requestToken(
    { grant_type: 'refresh_token', refresh_token: refreshToken },
    env,
  );

  /** @type {Record<string, unknown> | undefined} */
  let result;

  try {
    result = await response?.json();
  } catch {
    //
  }

  if (!response || !result) {
    return outputJSON({ error: 'token_request_failed' }, { status: 502, headers: corsHeaders });
  }

  // GitHub reports an invalid or expired refresh token with `200 OK` and an `error` property, which
  // the CMS handles, so the result is passed through as is
  return outputJSON(result, { status: response.status, headers: corsHeaders });
};

/**
 * Handle a CORS preflight request to the token endpoint.
 * @param {Request} request - HTTP request.
 * @param {{ [key: string]: string }} env - Environment variables.
 * @returns {Response} HTTP response.
 */
const handlePreflight = (request, env) =>
  new Response(null, { status: 204, headers: getCorsHeaders(request, env) ?? {} });

export default {
  /**
   * The main request handler.
   * @param {Request} request - HTTP request.
   * @param {{ [key: string]: string }} env - Environment variables.
   * @returns {Promise<Response>} HTTP response.
   * @see https://developers.cloudflare.com/workers/runtime-apis/fetch/
   * @see https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
   * @see https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app
   */
  async fetch(request, env) {
    const { method, url } = request;
    const { pathname } = new URL(url);

    if (method === 'GET' && ['/auth', '/oauth/authorize'].includes(pathname)) {
      return handleAuth(request, env);
    }

    if (method === 'GET' && ['/callback', '/oauth/redirect'].includes(pathname)) {
      return handleCallback(request, env);
    }

    if (['/auth', '/oauth/access_token'].includes(pathname)) {
      if (method === 'OPTIONS') {
        return handlePreflight(request, env);
      }

      if (method === 'POST') {
        return handleRefresh(request, env);
      }
    }

    return new Response('', { status: 404 });
  },
};
