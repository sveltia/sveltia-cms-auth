# Sveltia CMS Authenticator

This simple [Cloudflare Workers](https://workers.cloudflare.com/) script allows [Sveltia CMS](https://sveltiacms.app/en/) users to authenticate with GitHub through a [GitHub App](https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/about-creating-github-apps).

Unlike an OAuth app, a GitHub App only gets access to the repositories it’s installed on, with the permissions it needs, so users no longer have to grant access to all of their repositories, including private ones, just to edit one site.

<!-- prettier-ignore-start -->
> [!IMPORTANT]
> **In most cases, you don’t need this authenticator**. Sveltia CMS supports multiple authentication methods for GitHub and GitLab, so you can choose the one that best suits your needs without having to set up this OAuth client.
<!-- prettier-ignore-end -->

## When to use it

### You don’t need it if…

- You’re migrating from Netlify CMS or Decap CMS
  - Your site is being deployed to Netlify
    - You can keep using Netlify’s built-in OAuth client for Sveltia CMS without any changes to your CMS configuration.
  - You already use [another 3rd party OAuth client](https://decapcms.org/docs/external-oauth-clients/)
    - You can keep using it for Sveltia CMS without any changes to your CMS configuration.
- You’re using GitHub
  - You or technical users are the only users of your CMS instance
    - Use the [access token method](https://sveltiacms.app/en/docs/backends/github#access-token) instead.
- You’re using GitLab
  - This authenticator only supports GitHub. Use the [access token method](https://sveltiacms.app/en/docs/backends/gitlab#access-token) or [client-side PKCE authorization](https://sveltiacms.app/en/docs/backends/gitlab#pkce-authorization) instead.

### You may need it only if…

- You’re using GitHub
  - Non-technical users need to sign into the CMS
    - This authenticator will provide a better user experience than the access token method, which requires users to create and manage their own personal access tokens.

## How to use it

### Step 1. Deploy this project to Cloudflare Workers

Sign up with Cloudflare, and click the button below to start deploying.

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/sveltia/sveltia-cms-auth)

Alternatively, you can clone the project and run [`wrangler deploy`](https://developers.cloudflare.com/workers/wrangler/commands/#deploy) locally.

Once deployed, open your Cloudflare Workers dashboard, select the `sveltia-cms-auth` service, then the Worker URL (`https://sveltia-cms-auth.<SUBDOMAIN>.workers.dev`) will be displayed. Copy it for Step 2. It will also be used in Step 4.

### Step 2. Register the Worker as a GitHub App

Open the [Register new GitHub App page](https://github.com/settings/apps/new?name=Sveltia+CMS+Auth+for+YOUR_SITE&url=https://github.com/sveltia/sveltia-cms-auth&webhook_active=false&contents=write&pull_requests=write) on GitHub ([details](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app)). This link pre-fills most fields for you. To register the app under an organization instead of your personal account, replace `https://github.com/settings/apps/new` in the link with `https://github.com/organizations/YOUR_ORG/settings/apps/new`.

Edit these two fields:

- **GitHub App name**: Replace `YOUR_SITE` with your site name, or use any name you like. It must be unique on GitHub and up to 34 characters long
- **Redirect URI**: Enter `<YOUR_WORKER_URL>/callback`, using your Worker URL from Step 1

Review the other fields, which should already be set as follows:

- Expire user authorization tokens: Checked (recommended; see the note below)
- Request user authorization (OAuth) during installation: Unchecked
- Enable Device Flow: Unchecked
- Webhook > Active: Unchecked
- Repository permissions:
  - Contents: **Read and write** (pre-filled)
  - Metadata: **Read-only** (selected automatically)
  - Pull requests: **Read and write** (pre-filled; required for the [editorial workflow](https://sveltiacms.app/en/docs/workflows/editorial))
  - Workflows: **No access**; change it to **Read and write** only if users need to edit files under `.github/workflows`
- Where can this GitHub App be installed: **Only on this account**; change it to **Any account** if your site repository belongs to another account, such as an organization

Click **Create GitHub App**. Once registered, the app’s **Client ID** will be displayed. Copy and paste it to a text editor. We’ll use it in Step 3 below.

Select **Credentials** in the sidebar and click **New secret**. Copy and paste the generated secret to a text editor. We’ll use it in Step 3 below.

Install the app on the account that owns your site repository:

1. Select **Install App** in the sidebar, and click **Install** next to the account.
1. Under **for these repositories**, choose **Only select repositories**, click **Select repositories** and select your site repository.
1. Under **with these permissions**, make sure the app requests read access to metadata and read and write access to code and pull requests, plus workflows if you enabled them.
1. Click **Install**.

Anyone with write access to the repository can then sign into the CMS; they only need to authorize the app on their first sign-in, without installing it themselves. The authorization can be reviewed or revoked under **Settings** > **Applications** > **Authorized GitHub Apps**.

<!-- prettier-ignore-start -->
> [!NOTE]
> With token expiration enabled, a user access token expires after 8 hours, and Sveltia CMS refreshes it automatically through this authenticator using a refresh token, which is valid for 6 months. A user only has to sign in again after not using the CMS for that long. If you disable token expiration, the access token remains valid until it’s revoked, which is less secure.
<!-- prettier-ignore-end -->

<!-- prettier-ignore-start -->
> [!NOTE]
> The `auth_scope` backend option in Sveltia CMS has no effect with a GitHub App, because the app’s access is determined by its permissions and installations rather than OAuth scopes. Also, [Open Authoring](https://sveltiacms.app/en/docs/workflows/open) is not supported, as the app would have to be installed on each contributor’s fork.
<!-- prettier-ignore-end -->

### Step 3. Configure the Worker

Go back to the `sveltia-cms-auth` service page on the Cloudflare dashboard, select **Settings** > **Runtime variables and secrets**, and add the following environment variables to your Worker ([details](https://developers.cloudflare.com/workers/configuration/environment-variables/#add-environment-variables-via-the-dashboard)):

- `GITHUB_CLIENT_ID`: **Client ID** from Step 2
- `GITHUB_CLIENT_SECRET`: Secret from Step 2; check **Secret** next to the value to hide it
- `GITHUB_HOSTNAME`: Required only if you’re using GitHub Enterprise Server. Default: `github.com`
- `ALLOWED_DOMAINS`: (Optional) Your site’s hostname, e.g. `www.example.com`
  - Multiple hostnames can be defined as a comma-separated list, e.g. `www.example.com, www.example.org`
  - A wildcard (`*`) can be used to match any subdomain, e.g. `*.example.com`, which matches `www.example.com`, `blog.example.com`, `docs.api.example.com`, etc. (but not `example.com`)
  - To match a `www`-less naked domain and all the subdomains, use `example.com, *.example.com`
  - The list serves two purposes: it stops other sites from using your Worker at your expense (anti-abuse), and it stops them from obtaining an access token through it (security), because the authenticator releases a token only to a page served from one of these hostnames. Note that the list doesn’t stop someone who already has a user’s refresh token from refreshing it through the Worker outside a browser, so a refresh token should be kept as secret as the access token

<!-- prettier-ignore-start -->
> [!IMPORTANT]
> `ALLOWED_DOMAINS` is optional, but it’s both an anti-abuse and a security measure, so setting it is strongly recommended.
<!-- prettier-ignore-end -->

Save and deploy.

### Step 4. Update your CMS configuration

Open `admin/config.yml` locally or remotely, and add your Worker URL from Step 1 as the new `base_url` property under `backend`:

```diff
 backend:
   name: github
   repo: username/repo
   branch: main
+  base_url: <YOUR_WORKER_URL>
```

Commit the change. Once deployed, you can sign into Sveltia CMS remotely with GitHub!

## FAQ

### I’ve been using this authenticator with an OAuth app. How do I migrate to a GitHub App?

Register and install a GitHub App as described in Step 2, with the same `<YOUR_WORKER_URL>/callback` redirect URI as the OAuth app, then replace the `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` environment variables with the GitHub App’s credentials. No changes to your CMS configuration are needed. Users will be asked to authorize the new app on their next sign-in. Once everything works, you can delete the old OAuth app, which also revokes the tokens it issued.

An OAuth app still works with this authenticator, but it’s no longer documented here. If you keep using one, the optional `GITHUB_ALLOW_WORKFLOW_SCOPE` environment variable can be set to `true` to let a site request the `workflow` scope with Sveltia CMS’s `auth_scope` option.

### How do I sign in from a local development server with `ALLOWED_DOMAINS` set?

When running on `localhost`, Sveltia CMS sends `cms.netlify.com` to the authenticator as the site domain instead of `localhost`, unless the [`site_domain`](https://sveltiacms.app/en/docs/backends#site-domain) backend option is set. The authenticator also checks the hostname of the page that receives the token, which is `localhost` in this case. To sign in locally, do one of the following:

- Add both `localhost` and `cms.netlify.com` to `ALLOWED_DOMAINS`, e.g. `www.example.com, localhost, cms.netlify.com`
- Add `localhost` to `ALLOWED_DOMAINS`, and set the `site_domain` option to `localhost` in your local CMS configuration. Don’t deploy this configuration, or your live site will send `localhost` as well and fail to sign in

Don’t include a port number, such as `localhost:5173`, in `ALLOWED_DOMAINS`, as only the hostname is compared.

### What happened to GitLab support?

It has been removed. GitLab supports [client-side PKCE authorization](https://sveltiacms.app/en/docs/backends/gitlab#pkce-authorization), which doesn’t require a server like this one.

### Why do I have to set this thing up in the first place?

Technically, we could host Sveltia CMS Authenticator on our own server and let anyone use it, just like Netlify does. The cost probably wouldn’t matter because it’s just a small, short-lived script. However, running such a **service** certainly comes with legal, privacy and security liabilities that we cannot afford. Remember that Sveltia CMS is nothing more than [@kyoshino](https://github.com/kyoshino)’s personal project. That’s why the authenticator is not offered as SaaS and you have to install it yourself.

## Acknowledgements

This project was inspired by [`netlify-cms-oauth-firebase`](https://github.com/Herohtar/netlify-cms-oauth-firebase).
