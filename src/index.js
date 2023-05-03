export default {
  async fetch(request, env) {
    const { pathname, searchParams } = new URL(request.url);
    const { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, ALLOWED_DOMAINS } = env;

    if (pathname === '/auth') {
      const provider = searchParams.get('provider');
      const domain = searchParams.get('site_id');
      /** @see https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions#escaping */
      const escapeRegExp = (string) => string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

      // Check if the domain is whitelisted
      if (
        ALLOWED_DOMAINS &&
        !ALLOWED_DOMAINS.split(/,\s*/).some((rx) => domain.match(escapeRegExp(rx)))
      ) {
        return new Response('');
      }

      // GitHub
      if (provider === 'github' && GITHUB_CLIENT_ID) {
        return Response.redirect(
          `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&scope=repo,user`,
        );
      }
    }

    if (pathname === '/callback') {
      const code = searchParams.get('code');
      let provider;
      let token;
      let error;

      // GitHub
      if (GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET && code) {
        provider = 'github';

        try {
          const response = await fetch('https://github.com/login/oauth/access_token', {
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
        return new Response('');
      }

      const state = error ? 'error' : 'success';
      const content = error ? { error } : { provider, token };

      return new Response(
        `
          <!doctype html><html><body><script>
            (() => {
              window.addEventListener('message', ({ origin }) => {
                window.opener.postMessage(
                  'authorization:${provider}:${state}:${JSON.stringify(content)}',
                  origin
                );
              }, { once: true });
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
    }

    return new Response('');
  },
};
