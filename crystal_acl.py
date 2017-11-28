"""
Crystal ACL (Access Control) Middleware.

This filter manages the control to the swift objects based on the rules
introduced by the Crystal Dashboard (Policies --> Access Control panel).

This filter must be installed between the authtoken and the keystoneauth
middlewares: authtoken crystal_acl keystoneauth.

The authtoken middleware will take care of validating the user and
crystal_acl will authorize access, overriding the functionality of the
keystoneauth middleware.

In the case where there is no rule in the Crystal dashboard, the keystoneauth
will not be overridden.
"""
from swift.common.utils import get_logger
from swift.common.utils import register_swift_info
from swift.common.utils import list_from_csv
from swift.common.swob import HTTPNotFound, HTTPForbidden, HTTPUnauthorized
from swift.common.swob import wsgify
from swift.common.wsgi import make_subrequest
from swift.common.utils import config_read_reseller_options
import re
import redis
import json


class CrystalACL(object):

    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(self.conf, log_route='crystal_acl')
        self.reseller_admin_role = conf.get('reseller_admin_role',
                                            'ResellerAdmin').lower()
        self.reseller_prefixes, self.account_rules = \
            config_read_reseller_options(conf,
                                         dict(operator_roles=['admin', 'swiftoperator'],
                                              service_roles=[]))

        self.rcp = redis.ConnectionPool(host=conf['redis_host'],
                                        port=conf['redis_port'],
                                        db=conf['redis_db'])

    @wsgify
    def __call__(self, req):
        """
        Main hook into the WSGI paste.deploy filter/app pipeline.
        :param env: The WSGI environment dict.
        :param start_response: The WSGI start_response hook.
        :returns: Response as per WSGI.
        """
        env_identity = self._keystone_identity(req.environ)

        if env_identity:
            acc_acls, con_acls = self._get_crystal_acls(req)

            if not acc_acls and not con_acls:
                return req.get_response(self.app)

            return self.authorize(req, env_identity, acc_acls, con_acls)

    def _get_crystal_acls(self, req):
        part = req.split_path(1, 4, True)
        version, account, container, obj = part
        r = redis.Redis(connection_pool=self.rcp)

        acc_acls = None
        con_acls = None

        if account or container:
            account_id = account.replace(self._get_account_prefix(account), '')

        if account:
            acc_acls = r.hgetall('acl:'+account_id)
        if container:
            con_acls = r.hgetall('acl:'+account_id+':'+container)

        return acc_acls, con_acls

    def authorize(self, req, env_identity, acc_acls, con_acls):
        self.logger.debug('Using identity: %r', env_identity)

        req.environ['REMOTE_USER'] = env_identity.get('tenant')
        req.environ['keystone.identity'] = env_identity

        # Cleanup - make sure that a previously set swift_owner setting is
        # cleared now. This might happen for example with COPY requests.
        req.environ.pop('swift_owner', None)
        tenant_id, tenant_name = env_identity['tenant']
        user_id, user_name = env_identity['user']

        # allow OPTIONS requests to proceed as normal
        if req.method == 'OPTIONS':
            return self.allowed_response(req)

        try:
            part = req.split_path(1, 4, True)
            version, account, container, obj = part
        except ValueError:
            return HTTPNotFound(request=req)

        # Give unconditional access to a user with the reseller_admin
        # role.
        user_roles = [r.lower() for r in env_identity.get('roles', [])]
        user_service_roles = [r.lower() for r in env_identity.get(
                              'service_roles', [])]

        if self.reseller_admin_role in user_roles:
            msg = 'User %s:%s has reseller admin authorizing'
            self.logger.debug(msg, tenant_name, user_name)
            req.environ['reseller_request'] = True
            req.environ['swift_owner'] = True
            return self.allowed_response(req)

        # If we are not reseller admin and user is trying to delete its own
        # account then deny it.
        if not container and not obj and req.method == 'DELETE':
            # User is not allowed to issue a DELETE on its own account
            msg = 'User %s:%s is not allowed to delete its own account'
            self.logger.debug(msg, tenant_name, user_name)
            return self.denied_response(req)

        # Check if a user tries to access an account that does not match their
        # token
        if not self._account_matches_tenant(account, tenant_id):
            log_msg = 'Tenant mismatch: %s != %s'
            self.logger.debug(log_msg, account, tenant_id)
            return self.denied_response(req)

        # Check if user is account admin (admin role)
        account_prefix = self._get_account_prefix(account)
        operator_roles = self.account_rules[account_prefix]['operator_roles']
        have_operator_role = set(operator_roles).intersection(set(user_roles))
        service_roles = self.account_rules[account_prefix]['service_roles']
        have_service_role = set(service_roles).intersection(set(user_service_roles))
        allowed = False
        if have_operator_role and (service_roles and have_service_role):
            allowed = True
        elif have_operator_role and not service_roles:
            allowed = True

        if allowed:
            log_msg = 'Allow user with role(s) %s as account admin'
            self.logger.debug(log_msg, ','.join(have_operator_role.union(
                                                have_service_role)))
            req.environ['swift_owner'] = True
            return self.allowed_response(req)

        # Time to check Crystal Rules
        # Check container acls
        if con_acls:
            for _, acl in con_acls.items():
                acl = json.loads(acl)
                if user_id in acl['user_id']:
                    if req.method in ('GET', 'HEAD') and acl['list']:
                        allowed = account and container and not obj
                    else:
                        allowed = self._check_conditions(req, acl)
                    if allowed:
                        break

        # Check account acls in case the user is not allowed by a container acl
        if not allowed and acc_acls:
            for _, acl in acc_acls.items():
                acl = json.loads(acl)
                if user_id in acl['user_id']:
                    if req.method in ('GET', 'HEAD') and acl['list']:
                        allowed = account and not container and not obj
                    else:
                        allowed = self._check_conditions(req, acl)
                    if allowed:
                        break

        if allowed:
            log_msg = 'User %s:%s allowed in Crystal ACL: authorizing'
            self.logger.debug(log_msg, tenant_name, user_name)
            return self.allowed_response(req)
        else:
            log_msg = 'User %s:%s denied in Crystal ACL: none authorizing'
            self.logger.debug(log_msg, tenant_name, user_name)
            return self.denied_response(req)

    def _check_conditions(self, req, acl):
        allowed = False

        if req.method in ('GET', 'HEAD'):
            correct_type = True
            correct_tags = True

            if acl['object_type'] or acl['object_tag']:
                new_env = dict(req.environ)
                new_env['swift.authorize_override'] = True
                sub_req = make_subrequest(new_env, method='HEAD',
                                          path=req.path_info,
                                          headers=req.headers,
                                          swift_source='Crystal Filter Middleware')
                resp = sub_req.get_response(self.app)
                metadata = resp.headers

                if acl['object_type']:
                    object_name = acl['object_name']
                    filename = req.environ['PATH_INFO']
                    pattern = re.compile(object_name)
                    if not pattern.search(filename):
                        correct_type = False

                if acl['object_tag']:
                    tags = acl['object_tag'].split(',')
                    tag_checking = list()
                    for tag in tags:
                        key, value = tag.split(':')
                        if value.startswith('!'):
                            negative = True
                            value = value.strip('!')
                        else:
                            negative = False
                        meta_key = 'X-Object-Meta-'+key.title()
                        sysmeta_key = 'X-Object-Sysmeta-'+key.title()
                        correct_tag = (meta_key in metadata and
                                       metadata[meta_key] == value) or \
                                      (sysmeta_key in metadata and
                                       metadata[sysmeta_key] == value)
                        if negative:
                            tag_checking.append(not correct_tag)
                        else:
                            tag_checking.append(correct_tag)
                    correct_tags = all(tag_checking)

            allowed = acl['read'] and correct_type and correct_tags

        elif req.method in ('PUT', 'POST', 'DELETE'):
            allowed = acl['write']

        return allowed

    def _keystone_identity(self, environ):
        """Extract the identity from the Keystone auth component."""
        if (environ.get('HTTP_X_IDENTITY_STATUS') != 'Confirmed' or
           environ.get('HTTP_X_SERVICE_IDENTITY_STATUS') not in (None, 'Confirmed')):
            return
        roles = list_from_csv(environ.get('HTTP_X_ROLES', ''))
        service_roles = list_from_csv(environ.get('HTTP_X_SERVICE_ROLES', ''))
        identity = {'user': (environ.get('HTTP_X_USER_ID'),
                             environ.get('HTTP_X_USER_NAME')),
                    'tenant': (environ.get('HTTP_X_PROJECT_ID',
                                           environ.get('HTTP_X_TENANT_ID')),
                               environ.get('HTTP_X_PROJECT_NAME',
                                           environ.get('HTTP_X_TENANT_NAME'))),
                    'roles': roles,
                    'service_roles': service_roles}
        token_info = environ.get('keystone.token_info', {})
        auth_version = 0
        user_domain = project_domain = (None, None)
        if 'access' in token_info:
            # ignore any domain id headers that authtoken may have set
            auth_version = 2
        elif 'token' in token_info:
            auth_version = 3
            user_domain = (environ.get('HTTP_X_USER_DOMAIN_ID'),
                           environ.get('HTTP_X_USER_DOMAIN_NAME'))
            project_domain = (environ.get('HTTP_X_PROJECT_DOMAIN_ID'),
                              environ.get('HTTP_X_PROJECT_DOMAIN_NAME'))
        identity['user_domain'] = user_domain
        identity['project_domain'] = project_domain
        identity['auth_version'] = auth_version
        return identity

    def _account_matches_tenant(self, account, tenant_id):
        """Check if account belongs to a project/tenant"""
        for prefix in self.reseller_prefixes:
            if self._get_account_name(prefix, tenant_id) == account:
                return True
        return False

    def _get_account_prefix(self, account):
        """Get the prefix of an account"""
        # Empty prefix matches everything, so try to match others first
        for prefix in [pre for pre in self.reseller_prefixes if pre != '']:
            if account.startswith(prefix):
                return prefix
        if '' in self.reseller_prefixes:
            return ''
        return None

    def _get_account_name(self, prefix, tenant_id):
        return '%s%s' % (prefix, tenant_id)

    def allowed_response(self, req):
        """Allow WSGI Response.
        """
        req.environ['swift.authorize_override'] = True

        return req.get_response(self.app)

    def denied_response(self, req):
        """Deny WSGI Response.
        Returns a standard WSGI response callable with the status of 403 or 401
        depending on whether the REMOTE_USER is set or not.
        """
        if req.remote_user:
            return HTTPForbidden(request=req)
        else:
            return HTTPUnauthorized(request=req)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    conf['redis_host'] = conf.get('redis_host', 'controller')
    conf['redis_port'] = int(conf.get('redis_port', 6379))
    conf['redis_db'] = int(conf.get('redis_db', 0))

    register_swift_info('crystal_acl')

    def crystal_acl(app):
        return CrystalACL(app, conf)
    return crystal_acl
