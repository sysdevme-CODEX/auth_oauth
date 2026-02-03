
import json

import requests
import logging
from werkzeug import http, datastructures

if hasattr(datastructures.WWWAuthenticate, "from_header"):
    parse_auth = datastructures.WWWAuthenticate.from_header
else:
    parse_auth = http.parse_www_authenticate_header

from odoo import api, fields, models
from odoo.exceptions import AccessDenied, AccessError, UserError
from odoo.addons.auth_signup.models.res_users import SignupError
from odoo.http import request

_logger = logging.getLogger(__name__)

class ResUsers(models.Model):
    _inherit = 'res.users'

    oauth_provider_id = fields.Many2one('auth.oauth.provider', string='OAuth Provider')
    oauth_uid = fields.Char(string='OAuth User ID', help="Oauth Provider user_id", copy=False)
    oauth_access_token = fields.Char(string='OAuth Access Token Store', readonly=True, copy=False, prefetch=False, groups=fields.NO_ACCESS)
    has_oauth_access_token = fields.Boolean(string='Has OAuth Access Token', compute='_compute_has_oauth_access_token', groups='base.group_erp_manager')

    _uniq_users_oauth_provider_oauth_uid = models.Constraint(
        'unique(oauth_provider_id, oauth_uid)',
        'OAuth UID must be unique per provider',
    )

    @property
    def SELF_READABLE_FIELDS(self):
        return super().SELF_READABLE_FIELDS + ['has_oauth_access_token']

    @api.depends('oauth_access_token')
    def _compute_has_oauth_access_token(self):
        for user in self:
            user.has_oauth_access_token = bool(user.sudo().oauth_access_token)

    def remove_oauth_access_token(self):
        user = self.env.user
        if not (user.has_group('base.group_erp_manager') or self == user):
            raise AccessError(self.env._('You do not have permissions to remove the access token'))
        self.sudo().oauth_access_token = False

    def _auth_oauth_rpc(self, endpoint, access_token):
        if self.env['ir.config_parameter'].sudo().get_param('auth_oauth.authorization_header'):
            response = requests.get(endpoint, headers={'Authorization': 'Bearer %s' % access_token}, timeout=10)
        else:
            response = requests.get(endpoint, params={'access_token': access_token}, timeout=10)

        if response.ok: # nb: could be a successful failure
            return response.json()

        auth_challenge = parse_auth(response.headers.get("WWW-Authenticate"))
        if auth_challenge and auth_challenge.type == 'bearer' and 'error' in auth_challenge:
            return dict(auth_challenge)

        return {'error': 'invalid_request'}

    @api.model
    def _auth_oauth_validate(self, provider, access_token):
        """ return the validation data corresponding to the access token """
        oauth_provider = self.env['auth.oauth.provider'].browse(provider)
        validation = self._auth_oauth_rpc(oauth_provider.validation_endpoint, access_token)
        if validation.get("error"):
            raise Exception(validation['error'])
        if oauth_provider.data_endpoint:
            data = self._auth_oauth_rpc(oauth_provider.data_endpoint, access_token)
            validation.update(data)
        # unify subject key, pop all possible and get most sensible. When this
        # is reworked, BC should be dropped and only the `sub` key should be
        # used (here, in _generate_signup_values, and in _auth_oauth_signin)
        subject = next(filter(None, [
            validation.pop(key, None)
            for key in [
                'sub', # standard
                'id', # google v1 userinfo, facebook opengraph
                'user_id', # google tokeninfo, odoo (tokeninfo)
            ]
        ]), None)
        if not subject:
            raise AccessDenied(self.env._('Missing subject identity'))
        validation['user_id'] = subject

        return validation

    @api.model
    def _generate_signup_values(self, provider, validation, params):
        oauth_uid = validation['user_id']
        email = validation.get('email', 'provider_%s_user_%s' % (provider, oauth_uid))
        name = validation.get('name', email)
        return {
            'name': name,
            'login': email,
            'email': email,
            'oauth_provider_id': provider,
            'oauth_uid': oauth_uid,
            'oauth_access_token': params['access_token'],
            'active': True,
        }

    @api.model
    def _auth_oauth_signin(self, provider, validation, params):
        """ retrieve and sign in the user corresponding to provider and validated access token
            :param provider: oauth provider id (int)
            :param validation: result of validation of access token (dict)
            :param params: oauth parameters (dict)
            :return: user login (str)
            :raise: AccessDenied if signin failed

            This method can be overridden to add alternative signin methods.
        """
        oauth_uid = validation['user_id']
        try:
            oauth_user = self.search([("oauth_uid", "=", oauth_uid), ('oauth_provider_id', '=', provider)])
            if not oauth_user:
                raise AccessDenied()
            assert len(oauth_user) == 1
            oauth_user.write({'oauth_access_token': params['access_token']})
            return oauth_user.login
        except AccessDenied as access_denied_exception:
            if self.env.context.get('no_user_creation'):
                return None
            state = json.loads(params['state'])
            token = state.get('t')
            values = self._generate_signup_values(provider, validation, params)
            try:
                login, _ = self.signup(values, token)
                return login
            except (SignupError, UserError):
                raise access_denied_exception

    @api.model
    #that is correct auth with code instead of token, by sysdev
    def auth_oauth(self, provider, params):
        access_token = params.get('access_token')
        code = params.get('code')

        if code and not access_token:
            oauth_provider = self.env['auth.oauth.provider'].browse(provider)

            token_url = (oauth_provider.x_studio_token_url or '').strip()
            if not token_url:
                raise AccessDenied("Missing or undefined token url on OAuth Provider")

            redirect_url = (oauth_provider.x_studio_redirect_url or '').strip()
            if not redirect_url:
                raise AccessDenied("Missing or undefined redirect url on OAuth Provider")


            client_secret = (oauth_provider.x_studio_client_secret or '').strip()
            if not client_secret:
                raise AccessDenied("Missing or undefined client secret  on OAuth Provider")

            payload = {'grant_type': 'authorization_code','code': code,'client_id': oauth_provider.client_id,'client_secret': client_secret,'redirect_uri': redirect_url}
            _logger.info("Exchanging OAuth code for token at %s", token_url)


            resp = requests.post(token_url, data=payload, timeout=10)

            if not resp.ok:
                _logger.error("OAuth token exchange failed: %s", resp.text)
                raise AccessDenied("OAuth token exchange failed")

            token_data = resp.json()
            access_token = token_data.get('access_token')

            if not access_token:
                _logger.error("No access_token in OAuth response: %s", token_data)
                raise AccessDenied("No access_token returned by provider")
            
            params['access_token'] = access_token
            _logger.info("OAuth token exchange successful")

            if not access_token:
                raise AccessDenied("Missing access_token")


            validation = self._auth_oauth_validate(provider, access_token)
            _logger.warning(
                "OAuth validation: provider=%s user_id=%s email=%s",
                provider,
                validation.get('user_id'),
                validation.get('email'),
            )

            login = self._auth_oauth_signin(provider, validation, params)
            if not login:
                raise AccessDenied()

            _logger.error(
                "AUTH_OAUTH FINAL: login=%s provider=%s uid=%s token_present=%s",
                login,
                provider,
                validation.get("user_id"),
                bool(access_token),
            )
            return (self.env.cr.dbname, login, access_token)

    def _check_credentials(self, credential, env):
        try:
            return super()._check_credentials(credential, env)
        except AccessDenied:
            if not (credential['type'] == 'oauth_token' and credential['token']):
                raise
            passwd_allowed = env['interactive'] or not self.env.user._rpc_api_keys_only()
            if passwd_allowed and self.env.user.active:
                res = self.sudo().search([('id', '=', self.env.uid), ('oauth_access_token', '=', credential['token'])])
                if res:
                    return {
                        'uid': self.env.user.id,
                        'auth_method': 'oauth',
                        'mfa': 'default',
                    }
            raise

    def _get_session_token_fields(self):
        return super()._get_session_token_fields() | {'oauth_access_token'}
