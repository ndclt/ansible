#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Nicolas Duclert <nicolas.duclert@metronlab.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community',
}

DOCUMENTATION = r'''
---
module: keycloak_ldap_federation

short_description: Allows administration of Keycloak LDAP federation via Keycloak API

description:
    - This module allows  you to add, remove or modify Keycloak LDAP federation via the Keycloak API.
      It requires access to the REST API via OpenID Connect; the user connecting and the client being
      used must have the requisite access rights. In a default Keycloak installation, admin-cli
      and an admin user would work, as would a separate client definition with the scope tailored
      to your needs and a user having the expected roles.
    
    - The names of module options are snake_cased versions of the camelCase ones found in the
      Keycloak API and its documentation at U(http://www.keycloak.org/docs-api/3.3/rest-api/). 

    - At creation and update, this module allows you to test the connection or the authentication 
      to the LDAP service from the given arguments. If the connection or the authentication does
      not work, the module fails.

    - When updating a LDAP federation, where possible provide the group ID to the module. 
      This removes a lookup to the API to translate the name into the group ID.

version_added: "2.9"

options:
    state:
        description:
            - State of the LDAP federation.
            - On C(present), the group will be created if it does not yet exist, or updated with the parameters you provide.
            - On C(absent), the group will be removed if it exists.
        required: true
        default: present
        type: str
        choices:
            - present
            - absent

    realm:
        type: str
        description:
            - They Keycloak realm under which this LDAP federation resides.
        default: 'master'

    federation_id:
        description:
            - The name of the federation
            - Also called ID of the federationin the table of federations or
              the console display name in the detailed view of a federation
            - This parameter is mutually exclusive with federation_uuid and one
              of them is required by the module
        type: str
        aliases: [ federerationId ] 

    federation_uuid:
        description:
            - The uuid of the federation
            - This parameter is mutually exclusive with federation_id and one
              of them is required by the module
        type: str
        aliases: [ federationUuid ]

    enable:
        description:
            - whether the federation will be enable
        type: bool

    pagination:
        description:
            - Does the LDAP server supports pagination.
        type: bool

    vendor:
        description:
            - LDAP provider
            - Mandatory when creating the LDAP federation
        choices:
            - other
            - ad
            - rhds
            - tivoli
            - edirectory
        type: str

    username_ldap_attribute:
        description:
            - Name of the LDAP attribute to map to the Keycloak username
            - Mandatory when creating the LDAP federation
        type: str
        aliases: [ usernameLDAPAttribute, username_LDAP_attribute, usernameLdapAttribute ]

    rdn_ldap_attribute:
        description:
            - Name of the LDAP attribute to use as top attribute
            - Mandatory when creating the LDAP federation
        type: str
        aliases: [ rdnLDAPAttribute, rdnLdapAttribute, rdn_LDAP_attribute ]

    user_object_classes:
        description:
            - LDAP object class attributes for users
            - Mandatory when creating the LDAP federation
        type: list
        aliases: userObjectClasses

    connection_url:
        description: 
            - the url of the LDAP service
            - Mandatory when creating the LDAP federation
        type: str
        aliases: [ connectionUrl ]

    users_dn:
        description:
            - Full DN of LDAP tree where users are
            - Mandatory when creating the LDAP federation
        type: str
        aliases: [ usersDn ]

    bind_dn:
        description:
            - DN of LDAP admin
            - Mandatory when creating the LDAP federation
        type: str
        aliases: [ bindDn ]

    bind_credential:
        description:
            - Password of LDAP admin
            - Mandatory when creating the LDAP federation
        type: str
        aliases: [ bindCredential ]

    uuid_ldap_attribute:
        description:
            - Name of LDAP attribute which is used as unique object identifier
            for object in LDAP
            - Mandatory when creating the LDAP federation
        type: str
        aliases: [ uuidLDAPAttribute, uuidLdapAttribute, uuid_LDAP_attribute ]

    edit_mode:
        description:
            - The behaviour of the Keycloak with the LDAP.
        choices:
            - READ_ONLY
            - UNSYNCED
            - WRITABLE
        type: str
        aliases: [ editMode ]

    import_enable:
        description:
            - Whether to import the user from the LDAP into the Keycloak databases
        type: bool
        aliases: [ importEnable ]

    synchronize_registrations:
        description:
            - Should new user in the Keycloak be created within the LDAP
        type: bool
        aliases: [ sync_registrations, synchronizeRegistrations, syncRegistrations ]

    customer_user_ldap_filter:
        description:
            - Filter for searching user in the LDAP
        type: str
        aliases: [ customUserSearchFilter, custom_user_search_filter, customUserLdapFilter, customUserLDAPFilter, customUserLDAPFilter ]

    search_scope:
        description:
            - Set how users are search, on one level or in all the subtree
        type: str
        choices:
            - one level
            - subtree
        aliases: [ searchScope ]

    use_trustore_spi:
        description:
            - Whether LDAP connection will use the trustore SPI with the trustore conifgure in the standalone.xml
        type: str
        choices:
            - ldapsOnly
            - always
            - never
        aliases: [ useTruststoreSpi ]

    test_connection:
        description:
            - Check the connection to the LDAP server with a ping
            - This parameter is mutually exclusive with test_authentication
        type: bool
        aliases: [ testConnection ]

    test_authentication:
        description:
            - Check the connection to the LDAP server with the admin credentials
            - This parameter is mutually exclusive with test_connection
        type: bool
        aliases: [ testAuthentication ]

notes:
    - The following parameters existing in the UI are not taken into account in this module, I(importUser), I(validatePasswordPolicy), I(connectionPooling) (and all associated parameters), I(connectionTimeout), I(readTimeout), I(allowKerberosAuthentication) (and all associated parameters), I(useKerberosForPasswordAuthentication), I(batchSize), I(periodicFullSync), I(periodicChangedUserSync) and I(cachePolicy). 

extends_documentation_fragment:
    - keycloak

author:
    - Nicolas Duclert (@ndclt)
'''

EXAMPLES = r'''
- name: Create a keycloak federation
  keycloak_ldap_federation:
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    realm: master
    name: my-company-ldap
    state: present
    edit_mode: WRITABLE
    synchronize_registrations: True,
    username_ldap_attribute: cn
    rdn_ldap_attribute: cn
    user_object_classes: inetOrgPerson, organizationalPerson
    connection_url: ldap://openldap
    users_dn: ou=People,dc=my-company
    bind_dn: cn=admin,dc=my-company
    bind_credential: ldap_admin_password
    uuid_ldap_attribute: entryUUID
    search_scope: subtree
    use_truststore_spi: never
    test_authentication: True
'''

RETURN = r'''
msg:
  description: Message as to what action was taken
  returned: always
  type: str
  sample: "LDAP federation created."

changed:
  description: whether the state of the keycloak configuration change
  returned: always
  type: bool

ldap_federation:
  description: the LDAP federation representation empty if the asked federation is deleted or does not exist.
  returned: always
  type: dict
  contains:
    id:
      description: UUID that identifies the LDAP federation
      type: str
      returned: on success
      sample: de455375-6900-46a0-8d11-51554e1c3f18
    name:
      description: the name of the LDAP federation
      type: str
      returned: on success
      sample: my-company-ldap
    providerId:
      description: the id of the federation, always ldap for this module
      type: str
      returned: on success
      sample: ldap
    providerType:
      description: the type of the federation, always org.keycloak.storage.UserStorageProvider
      type: str
      returned: on success
      sample: org.keycloak.storage.UserStorageProvider
    parentId:
      description: the parent of the federation
      type: str
      returned: on success
      sample: master
    config:
      description: the configuration of the LDAP federation
      type: dict:
      returned: always
      contains:
        pagination:
          description: whether the LDAP server supports pagination
          type: bool
          returned: on success
          sample: true
        fullSyncPeriod:
          description: whether to periodic synchronize the Keycloak and the LDAP
          type: int
          returned: on success
          sample: -1
        usersDn:
          description: Full DN of LDAP tree where users are
          type: str
          returned: always
          sample: ou=People, dc=MyCompany
        connectionPooling:
          description: whether to use connection pooling for accessing the LDAP server
          type: bool
          returned: on success
          sample: true
        cachePolicy:
          description: cache policy for storage provider
          type: str
          returned: on success
          sample: DEFAULT
        useKerberosForPasswordAuthentication:
          description: whether to use Kerberos for password authentication
          type: bool
          returned: on success
          sample: false
        importEnabled:
          description: whether to save the LDAP users in the Keycloak database
          type: bool
          returned: on success
          sample: false
        enabled:
          description: whether to enable the LDAP federation
          type: bool
          returned: always
          sample: false
        bindCredential:
          description: the admin password 
          type: str
          returned: on success
          sample: admin_password
        changedSyncPeriod:
          description: whether periodic synchronization of new or changed users should be enable
          type: int
          returned: on success
          sample: -1
        bindDn:
          description: DN of LDAP admin
          type: str
          returned: on success
          sample: cn=admindc=Metrondc=io
        usernameLDAPAttribute:
          description: Name of the LDAP attribute to map to the Keycloak username
          type: str
          returned: on success
          sample: uuid
        vendor:
          description: LDAP provider
          type: str
          returned: on success
          sample: other
        uuidLDAPAttribute:
          description: Name of LDAP attribute which is used as unique object identifier for object in LDAP
          type: str
          returned: on success
          sample: entryUUID
        allowKerberosAuthentication:
          description: whether to allow Kerberos authentication
          type: bool
          returned: on success
          sample: false
        connectionUrl:
          description: the url of the LDAP service
          type: str
          returned: on success
          sample: ldap://openldap
        syncRegistrations:
          description: Whether new user created in the Keycloak should be created within the LDAP
          type: bool
          returned: on success
          sample: true
        authType:
          description: LDAP authentication type (simple or none)
          type: str
          returned: on success
          sample: simple
        debug:
          description: whether the debug mode is activated
          type: bool
          returned: on success
          sample: false
        searchScope:
          description: Set how users are search, on one level (1) or in all the subtree (2)
          type: int
          returned: on success
          sample: 1
        useTruststoreSpi:
          description: Whether LDAP connection will use the trustore SPI with the trustore conifgure in the standalone.xml
          type: str
          returned: on success
          sample: ldapsOnly
        priority:
          description: priority of the provider when doing an user lookup (lowest first) 
          type: int
          returned: on success
          sample: 0
        userObjectClasses:
          description: LDAP object class attributes for users
          type: str
          returned: on success
          sample: inetOrgPerson, organizationalPerson
        rdnLDAPAttribute:
          description: Name of the LDAP attribute to use as top attribute
          type: str
          returned: on success
          sample: entryUUID
        editMode:
          description: The behaviour of the Keycloak with the LDAP.
          type: str
          returned: on success
          sample: READ_ONLY
        validatePasswordPolicy:
          description: whether Keycloak should validate the password with the realm password policy before updating it
          type: bool
          returned: on success
          sample: false
        batchSizeForSync:
          description: Count of LDAP users to be imported from the LDAP to Keycoak within single transaction
          type: int
          returned: on success
          sample: 1000
        evictionDay:
          description: Day of the week the entry will become invalid on (1 is Sunday)
          type: int
          returned: on success
          sample: 1 
        evictionHour:
          description: Hour of the week the entry will become invalid on
          type: int
          returned: on success
          sample: 2
        evictionMinute:
          description: Minute of the week the entry will become invalid on
          type: int
          returned: on success
          sample: 20
        maxLifespan:
          description: Max lifespan of cache entry in millisecond
          type: int
          returned: on success
          sample: 1000
        customUserSearchFilter:
          description: Filter for searching user in the LDAP
          type: str
          returned: on success
          sample: 
        connectionPoolingAuthentication:
          description: Authentication type that may be pooled
          type: str
          returned: on success
          sample: simple
        connectionPoolingDebug:
          description: The level of debug output to produce
          type: int
          returned: on success
          sample: fine
        connectionPoolingInitSize:
          description: the number of connection per connection indentity to create when initialy createing a connection for the identity
          type: str
          returned: on success
          sample: "2"
        connectionPoolingMaxSize:
          description: the maximum number of connection per connection indentity that can be maintained concurrently
          type: str
          returned: on success
          sample: 1000
        connectionPoolingPrefSize:
          description: the maximum number of connection per connection indentity that should be maintained concurrently
          type: str
          returned: on success
          sample: 5
        connectionPoolingProtocol:
          description: Protocol types of connection that may be pooled (plain or ssl)
          type: str
          returned: on success
          sample: plain ssl
        connectionPoolingTimeout:
          description: the number of milliseconds that an idle connection may remain in the pool without being closed and removed from the pool
          type: str
          returned: on success
          sample:  1000
        connectionTimeout:
          description: LDAP connection timeout in milliseconds
          type: str
          returned: on success
          sample: 1000
        readTimeout:
          description: LDAP timeout in milliseconds for read operations
          type: str
          returned: on success
          sample: 1000
        serverPrincipal:
          description: Full name of Kerberos server principal for hhtp service including serv and domain name.
          type: str
          returned: on success
          sample: HTTP/host.foo.org@FOO.ORG
        keyTab:
          description: Location of Kerberos keytab file containing the credentials of server principal
          type: str
          returned: on success
          sample: /etc/krb5.keytab
        kerberosRealm:
          description: Name of Kerberos realm
          type: str
          returned: on success
          sample: FOO.ORG
'''

import json
from copy import deepcopy
from ansible.module_utils._text import to_text
from ansible.module_utils.identity.keycloak.keycloak import (
    camel,
    keycloak_argument_spec,
    KeycloakAuthorizationHeader,
)
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.parse import quote, urlencode
from ansible.module_utils.six.moves.urllib.error import HTTPError


USER_FEDERATION_URL = '{url}/admin/realms/{realm}/components?parent={realm}&type=org.keycloak.storage.UserStorageProvider&name={federation_id}'
USER_FEDERATION_BY_UUID_URL = '{url}/admin/realms/{realm}/components/{uuid}'
COMPONENTS_URL = '{url}/admin/realms/{realm}/components/'
TEST_LDAP_CONNECTION = '{url}/admin/realms/{realm}/testLDAPConnection'


SEARCH_SCOPE = {'one level': 1, 'subtree': 2}


class LdapFederation(object):
    """Keycloak LDAP Federation class.
    """
    def __init__(self, module, connection_header):
        self.module = module
        self.restheaders = connection_header
        self.federation = self.get_federation()
        try:
            self.uuid = self.federation['id']
        except KeyError:
            self.uuid = ''

    def _get_federation_url(self):
        """Create the url in order to get the federation from the given argument (uuid or name)
        :return: the url as string
        :rtype: str
        """
        try:
            return USER_FEDERATION_BY_UUID_URL.format(
                url=self.module.params.get('auth_keycloak_url'),
                realm=quote(self.module.params.get('realm')),
                uuid=self.uuid,
            )
        except AttributeError:
            if self.module.params.get('federation_id'):
                return USER_FEDERATION_URL.format(
                    url=self.module.params.get('auth_keycloak_url'),
                    realm=quote(self.module.params.get('realm')),
                    federation_id=quote(self.module.params.get('federation_id')),
                )
            return USER_FEDERATION_BY_UUID_URL.format(
                url=self.module.params.get('auth_keycloak_url'),
                realm=quote(self.module.params.get('realm')),
                uuid=quote(self.module.params.get('federation_uuid')),
            )

    def get_federation(self):
        """Get the federation information from keycloak

        :return: the federation representation as a dictionary, if the asked
        representation does not exist, a empty dictionary is returned.
        :rtype: dict
        """
        get_url = self._get_federation_url()
        realm = self.module.params.get('realm')
        try:
            json_federation = json.load(
                open_url(
                    get_url,
                    method='GET',
                    headers=self.restheaders.header,
                    validate_certs=self.module.params.get('validate_certs'),
                )
            )
        except HTTPError as e:
            if e.code == 404:
                return {}
            else:
                self.module.fail_json(
                    msg='Could not obtain user federation %s for realm %s: %s'
                    % (to_text(self.given_id), to_text(realm), to_text(e))
                )
        except ValueError as e:
            self.module.fail_json(
                msg=(
                    'API returned incorrect JSON when trying to obtain user '
                    'federation %s for realm %s: %s'
                )
                % (to_text(self.given_id), to_text(realm), to_text(e))
            )
        except Exception as e:
            self.module.fail_json(
                msg='Could not obtain user federation %s for realm %s: %s'
                % (to_text(self.given_id), to_text(realm), to_text(e))
            )
        else:
            if json_federation:
                try:
                    return json_federation[0]
                except KeyError:
                    return json_federation
            return {}

    @property
    def given_id(self):
        """Get the asked id given by the user.

        :return the asked id given by the user as a name or an uuid.
        :rtype: str
        """
        if self.module.params.get('federation_id'):
            return self.module.params.get('federation_id')
        return self.module.params.get('federation_uuid')

    def delete(self):
        """Delete the federation"""
        federation_url = self._get_federation_url()
        try:
            open_url(
                federation_url,
                method='DELETE',
                headers=self.restheaders.header,
                validate_certs=self.module.params.get('validate_certs'),
            )
        except Exception as e:
            self.module.fail_json(
                msg='Could not delete federation %s in realm %s: %s'
                % (self.given_id, self.module.params.get('realm'), str(e))
            )

    def update(self):
        """Update the federation

        :return: the representation of the updated federation
        :rtype: dict
        """
        federation_payload = self._create_payload()
        put_url = USER_FEDERATION_BY_UUID_URL.format(
            url=self.module.params.get('auth_keycloak_url'),
            realm=quote(self.module.params.get('realm')),
            uuid=self.uuid,
        )
        if self.module.params.get('test_connection'):
            self._test_connection()
        if self.module.params.get('test_authentication'):
            self._test_connection()
            self._test_authentication()
        try:
            open_url(
                put_url,
                method='PUT',
                headers=self.restheaders.header,
                validate_certs=self.module.params.get('validate_certs'),
                data=json.dumps(federation_payload),
            )
        except Exception as e:
            self.module.fail_json(
                msg='Could not create federation %s in realm %s: %s'
                % (self.given_id, self.module.params.get('realm'), str(e))
            )
        return self._clean_payload(federation_payload)

    def create(self):
        """Create the federation from the given arguments.

        Before create the federation, there is a check concerning the mandatory
        arguments waited by keycloak.
        If asked by the user, before creating the federation, the connection or
        the authentication can be tested.

        :return: the representation of the updated federation
        :rtype: dict
        """
        federation_payload = self._create_payload()
        self.check_mandatory_arguments(federation_payload)
        post_url = COMPONENTS_URL.format(
            url=self.module.params.get('auth_keycloak_url'),
            realm=quote(self.module.params.get('realm')),
        )
        if self.module.params.get('test_connection'):
            self._test_connection()
        if self.module.params.get('test_authentication'):
            self._test_connection()
            self._test_authentication()
        try:
            open_url(
                post_url,
                method='POST',
                headers=self.restheaders.header,
                validate_certs=self.module.params.get('validate_certs'),
                data=json.dumps(federation_payload),
            )
        except Exception as e:
            self.module.fail_json(
                msg='Could not create federation %s in realm %s: %s'
                % (self.given_id, self.module.params.get('realm'), str(e))
            )
        return self._clean_payload(federation_payload)

    def _test_connection(self):
        """Test the connection to the LDAP server"""
        if not self._call_test_url({'action': 'testConnection'}):
            self.module.fail_json(
                msg='The url connection %s cannot be reached.'
                % (self.module.params.get('connection_url'))
            )

    def _test_authentication(self):
        """Test the authentication to the LDAP server with the given binding credentials."""
        if not self._call_test_url({'action': 'testAuthentication'}):
            self.module.fail_json(
                msg='The user %s cannot logged in the ldap at %s, '
                'you should check your credentials.'
                % (
                    self.module.params.get('bind_dn'),
                    self.module.params.get('connection_url'),
                )
            )

    def _call_test_url(self, extra_arguments):
        """Call the keycloak url testing credentials against the LDAP server.

        The same url is called for connection and authentication, only the
        extra_arguments given by calling function is necessary for changing
        the tested functionality.
        The connection or authentication failure is identified with the 400
        http status code.

        :param extra_arguments: a dictionary with the action to do (
        authentication or connection)
        :return: a boolean showing if the connection or the authentication
        works.
        """
        payload = {
            'bindCredential': self.module.params.get('bind_credential', ''),
            'bindDn': self.module.params.get('bind_dn', ''),
            'connectionUrl': self.module.params.get('connection_url'),
            'connectionTimeout': '',
            'realm': self.module.params.get('realm'),
            'useTruststoreSpi': self.module.params.get('useTruststoreSpi', 'ldapsOnly'),
        }
        payload.update(extra_arguments)
        test_url = TEST_LDAP_CONNECTION.format(
            url=self.module.params.get('auth_keycloak_url'),
            realm=self.module.params.get('realm'),
        )
        headers = deepcopy(self.restheaders.header)
        headers.update(
            {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
        )
        try:
            open_url(
                test_url,
                method='POST',
                headers=headers,
                validate_certs=self.module.params.get('validate_certs'),
                data=urlencode(payload),
            )
        except HTTPError as http_error:
            if http_error.code == 400:
                return False
            self.module.fail_json(
                msg='Could not test connection %s in realm %s: %s'
                % (self.given_id, self.module.params.get('realm'), str(http_error))
            )
        except Exception as e:
            self.module.fail_json(
                msg='Could not test connection %s in realm %s: %s'
                % (self.given_id, self.module.params.get('realm'), str(e))
            )
        return True

    def _create_payload(self):
        """Create the payload for updating or creating a LDAP federation.

        Keycloak is waiting for a particular type of json for a LDAP federation:
        {
          'providerId': 'ldap',
          'providerType': 'org.keycloak.storage.UserStorageProvider',
          'config': {user parameters}
        }.
        And all user parameters must be in a list of one element.

        :return: the payload to put in the post or put request.
        :rtype: dict
        """
        translation = {'federation_id': 'name', 'federation_uuid': 'id'}
        config = {}
        payload = {
            'providerId': 'ldap',
            'providerType': 'org.keycloak.storage.UserStorageProvider',
        }
        not_federation_argument = list(keycloak_argument_spec().keys()) + [
            'state',
            'realm',
        ]
        for key, value in self.module.params.items():
            if value is not None and key not in not_federation_argument:
                if key in list(translation.keys()):
                    payload.update({translation[key]: value})
                else:
                    if key == 'search_scope':
                        config.update({camel(key): [SEARCH_SCOPE[value]]})
                    else:
                        config.update({camel(key).replace('Ldap', 'LDAP'): [value]})
        try:
            config['priority']
        except KeyError:
            config.update({'priority': [0]})
        # yet I don't need connection pooling to True but this key is mandatory.
        config.update({'connectionPooling': [False]})
        payload.update({'config': config})
        return payload

    def get_result(self):
        """Get the payload cleaned of credentials and lists.

        :return: the cleaned payload
        :rtype: dict
        """
        return self._clean_payload(self._create_payload())

    @staticmethod
    def _clean_payload(payload):
        """Clean the payload from credentials and extra list.

        :param payload: the payload given to the post or put request.
        :return: the cleaned payload
        :rtype: dict
        """
        clean_payload = deepcopy(payload)
        old_config = clean_payload.pop('config')
        new_config = {}
        for key, value in old_config.items():
            if key != 'bindCredential':
                new_config.update({key: value[0]})
            else:
                new_config.update({key: 'no_log'})
        clean_payload.update({'config': new_config})
        return clean_payload

    def check_mandatory_arguments(self, creation_payload):
        """Check if mandatory arguments for federation creation are present.

        If there are not present, this function exits the module with a fail_json.

        :param creation_payload: the payload to send to the post request.
        """
        mandatory_elements = [
            'priority',
            'vendor',
            'username_ldap_attribute',
            'rdn_ldap_attribute',
            'uuid_ldap_attribute',
            'user_object_classes',
            'connection_url',
            'users_dn',
            'bind_dn',
            'bind_credential',
        ]
        missing_element = []
        for one_mandatory in mandatory_elements:
            search_key = camel(one_mandatory).replace('Ldap', 'LDAP')
            if search_key not in creation_payload['config']:
                missing_element.append(one_mandatory)
        if not missing_element:
            return None
        if len(missing_element) > 1:
            missing_element.sort()
            elements_for_message = ', '.join(missing_element[:-1])
            elements_for_message += ' and {} are missing'.format(missing_element[-1])
        else:
            elements_for_message = missing_element[0] + 'is missing'
        elements_for_message += ' for the federation creation.'
        self.module.fail_json(msg=elements_for_message)


def run_module():
    argument_spec = keycloak_argument_spec()
    meta_args = dict(
        state=dict(type='str', default='present', choices=['present', 'absent']),
        realm=dict(type='str', default='master'),
        federation_id=dict(type='str', aliases=['federerationId']),
        federation_uuid=dict(type='str', aliases=['federationUuid']),
        enable=dict(type='bool'),
        pagination=dict(type='bool'),
        vendor=dict(type='str', choices=['other', 'ad', 'rhds', 'tivoli', 'edirectory']),
        edit_mode=dict(
            type='str',
            choices=['READ_ONLY', 'UNSYNCED', 'WRITABLE'],
            aliases=['editMode'],
        ),
        import_enable=dict(type='bool', aliases=['importEnable']),
        synchronize_registrations=dict(
            type='bool',
            aliases=[
                'sync_registrations',
                'synchronizeRegistrations',
                'syncRegistrations',
            ],
        ),
        username_ldap_attribute=dict(
            type='str',
            aliases=[
                'usernameLDAPAttribute',
                'username_LDAP_attribute',
                'usernameLdapAttribute',
            ],
        ),
        rdn_ldap_attribute=dict(
            type='str',
            aliases=['rdnLDAPAttribute', 'rdnLdapAttribute', 'rdn_LDAP_attribute'],
        ),
        user_object_classes=dict(type='str', aliases=['userObjectClasses']),
        connection_url=dict(type='str', aliases=['connectionUrl']),
        users_dn=dict(type='str', aliases=['usersDn']),
        bind_dn=dict(type='str', aliases=['bindDn']),
        bind_credential=dict(type='str', aliases=['bindCredential'], no_log=True),
        custom_user_ldap_filter=dict(
            type='str',
            aliases=[
                'customUserSearchFilter',
                'custom_user_search_filter',
                'customUserLdapFilter',
                'customUserLDAPFilter',
                'custom_user_LDAP_filter',
            ],
        ),
        uuid_ldap_attribute=dict(
            type='str',
            aliases=['uuidLDAPAttribute', 'uuidLdapAttribute', 'uuid_LDAP_attribute'],
        ),
        search_scope=dict(
            type='str', choices=['one level', 'subtree'], aliases=['searchScope']
        ),
        use_truststore_spi=dict(
            type='str',
            choices=['ldapsOnly', 'always', 'never'],
            aliases=['useTruststoreSpi'],
        ),
        test_connection=dict(type='bool', aliases=['testConnection']),
        test_authentication=dict(type='bool', aliases=['testAuthentication']),
    )
    # option not taken into account:
    # cache_policy=dict(type=str, choices=['DEFAULT', 'EVICT_DAILY', 'EVICT_WEEKLY', 'MAX_LIFESPAN'], aliases=['cachePolicy'])
    # authentication_type: (authType in json) value: ["simple", "none"], default simple

    argument_spec.update(meta_args)

    # The id of the role is unique in keycloak and if it is given the
    # client_id is not used. In order to avoid confusion, I set a mutual
    # exclusion.
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_one_of=[['federation_id', 'federation_uuid']],
        mutually_exclusive=[
            ['federation_id', 'federation_uuid'],
            ['test_connection', 'test_authentication'],
        ],
    )
    connection_header = KeycloakAuthorizationHeader(
        base_url=module.params.get('auth_keycloak_url'),
        validate_certs=module.params.get('validate_certs'),
        auth_realm=module.params.get('auth_realm'),
        client_id=module.params.get('auth_client_id'),
        auth_username=module.params.get('auth_username'),
        auth_password=module.params.get('auth_password'),
        client_secret=module.params.get('auth_client_secret'),
    )
    ldap_federation = LdapFederation(module, connection_header)
    waited_state = module.params.get('state')
    result = {}
    if waited_state == 'absent':
        if not ldap_federation.federation:
            result['msg'] = to_text(
                'Federation {given_id} does not exist, doing nothing.'.format(
                    given_id=ldap_federation.given_id
                )
            )
            result['changed'] = False
        else:
            if not module.check_mode:
                ldap_federation.delete()
            result['msg'] = to_text(
                'Federation {given_id} deleted.'.format(
                    given_id=ldap_federation.given_id
                )
            )
            result['changed'] = True
        result['ldap_federation'] = {}
    else:
        if not ldap_federation.federation:
            if not module.check_mode:
                payload = ldap_federation.create()
            else:
                payload = ldap_federation.get_result()

            result['msg'] = to_text(
                'Federation {given_id} created.'.format(
                    given_id=ldap_federation.given_id
                )
            )
            result['changed'] = True
            result['ldap_federation'] = payload
        else:
            if not module.check_mode:
                payload = ldap_federation.update()
            else:
                payload = ldap_federation.get_result()
            result['msg'] = to_text(
                'Federation {given_id} updated.'.format(
                    given_id=ldap_federation.given_id
                )
            )
            result['changed'] = True
            result['ldap_federation'] = payload

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
