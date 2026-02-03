**What Was Added**

Support for OAuth2 Authorization Code → Access Token exchange
Token exchange performed inside res.users.auth_oauth()
Provider-specific configuration via OAuth Provider form (Studio fields)
No hard-coded secrets or URLs
Compatible with existing OAuth providers and flows

**Compatibility**

Odoo version: 19
OAuth providers: Tested with Authentik
Backward compatibility: **Yes**
(providers already returning access_token continue to work)

**Security Notes**

client_secret is stored in provider configuration, not in code
Access is restricted to base.group_system
OAuth token handling relies on Odoo’s native authentication pipeline
No changes to password or MFA logic

**OAuth Flow (Updated)**

- User authenticates at OAuth provider (e.g. Authentik)
- Provider redirects back to Odoo with code
- Odoo exchanges code for access_token
- Standard Odoo OAuth flow continues:
- token validation
- user lookup / signup
 -session authentication

**Motivation**

Many OAuth providers (including Authentik and thanks to this service :) it was done) enforce the authorization code flow and do not return access tokens directly to clients.
This patch enables Odoo 19 to integrate with such providers without proxy layers or external middleware, while preserving Odoo’s native security model.

**Provider Configuration**

The following fields are added to OAuth Provider (auth.oauth.provider)
(via Odoo Studio or direct in XML view, therefore prefixed with x_studio_):

Field	Description
x_studio_token_url	OAuth provider Token Endpoint
x_studio_redirect_url	Redirect URI used during code exchange
x_studio_client_secret	OAuth client secret
