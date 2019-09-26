#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Nicolas Duclert <nicolas.duclert@metronlab.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1', 'status': ['preview'], 'supported_by': 'community'}

DOCUMENTATION = r'''
module: keycloak_client_scope_crud

short_description: Allows administration of Keycloak client scope via Keycloak API
description:
  - This module allows you to add, remove or modify Keycloak client scopes via the Keycloak API.
    It requires access to the REST API via OpenID Connect; the user connecting and the client being
    used must have the requisite access rights. In a default Keycloak installation, admin-cli
    and an admin user would work, as would a separate client definition with the scope tailored
    to your needs and a user having the expected roles.

  - This module has been tested against keycloak 6.0, the backward compatibility is not guaranteed. 

version_added: "2.10"
options:
  state:
    description:
      - State of the client scopes.
      - On C(present), the client scope will be created if it does not yet exist, or updated with the parameters you provide.
      - On C(absent), the client scope will be removed if it exists.
    required: true
    default: present
    type: str
    choices:
      - present
      - absent

  realm:
    type: str
    description:
      - They Keycloak realm under which this client scope resides.
    default: master
  
  client_scopes_name:
    type: str
    description:
      - the name of the client scope
      - this name must be unique in the realm, when updating a client scope this will be checked
      - if this parameter is given with I(client_scopes_uuid), I(client_scopes_uuid) takes precedence.
      - Either this parameter or I(client_scopes_uuid) is required

  client_scopes_uuid:
    type: str
    description:
      - the uuid of the client scope
      - if this parameter is given with I(client_scopes_name), this parameter takes precedence.
      - Either this parameter or I(client_scopes_uuid) is required
  
  protocol:
    type: str
    description:
      - which SSO protocol configuration is being supplied by this client scope
    choices:
      - openid-connect
      - saml

  include_in_token_scope:
    type: bool
    description:
      - this parameter cannot be given when I(protocol=saml)
      - if C(True), the name of this client scope will be added to the access token property scope

  gui_order:
    type: int
    description:
      - specify order of the provider in graphical user interface (e.g. in consent page)

  description:
    type: str
    description:
      - description of the client scope

  display_on_consent_screen:
    type: bool
    description:
      - if C(True) and this client scope is added to some client with consent required, then the text specified by I(consent_screen_text) will be display on consent screen. 

  consent_screen_text:
    type: str
    description:
      - text which will be shown on consent scree when this client scope is added to some client with consent required
'''

EXAMPLES = r'''
- name: Minimal client scope creation
  keycloak_client_scope_crud:
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    realm: master
    state: present
    client_scopes_name: my-scope
- name: Full client scope creation
  keycloak_client_scope_crud:
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    realm: master
    state: present
    client_scopes_name: my-scope
    protocol: openid-connect
    include_in_token_scope: yes
    gui_order: 1
    description: a nice description of my scope
    display_on_consent_screen: yes
    consent_screen_text: do you agree
'''

RETURN = r'''
msg:
  description: Message as to what action was taken
  returned: always
  type: str
  sample: Client scopes new-client-scope-saml created

changed:
  description: whether the state of the keycloak configuration change
  returned: always
  type: bool

client_scopes:
  description: the client scope representation
  returned: always
  type: dict
  contains:
    name:
      description: name of the client scope
      type: str
      returned: on success
      sample: my-scope
    id:
      description: uuid of the client scope
      type: str
      returned: on success
      sample: 30c244a5-503e-47d8-9a65-ac0c44088ba9
    description:
      description: description of the client scope
      type: str
      returned: on success
      sample: a description of my-scope
    protocol:
      description: which SSO protocol configuration is being supplied by this client scope
      type: str
      returned: on success
      sample: openid-connect
    attributes:
      description: the attributes associate to the protocol
      type: dict
      returned: on success
      contains:
        include.in.token.scope:
          description: add the name of this client scope to the access token property scope when protocol is openid-connect
          type: bool
          sample: True
        display.on.consent.screen:
          description: add the client scope is added to some client with consent required
          type: bool
          sample: True
        gui.order:
          description: specify order of the provider in graphical user interface
          type: int
          sample: 1
        consent.screen.text:
          description: text which will be shown on consent scree when this client scope is added to some client with consent required
          type: str
          sample: some consent text
'''

from itertools import filterfalse

from ansible.module_utils.basic import AnsibleModule

from ansible.module_utils.identity.keycloak.utils import snake_to_point_case, convert_to_bool
from ansible.module_utils.identity.keycloak.keycloak import (
    KeycloakError,
    keycloak_argument_spec,
    get_token,
    get_on_url,
    delete_on_url,
    post_on_url,
    put_on_url,
)
from ansible.module_utils.common.dict_transformations import recursive_diff

from ansible.module_utils.identity.keycloak.crud import crud_with_instance
from ansible.module_utils.six.moves.urllib.parse import quote


CLIENT_SCOPES_BY_NAME_URL = '{url}/admin/realms/{realm}/client-scopes'
CLIENT_SCOPES_BY_UUID_URL = '{url}/admin/realms/{realm}/client-scopes/{client_scopes_uuid}'


class ClientScopes(object):
    def __init__(self, module, connection_header):
        self.module = module
        self.restheaders = connection_header
        self.uuid = self.module.params.get('client_scopes_uuid')
        self.description = 'client scopes {given_id}'.format(given_id=self.given_id)
        self.initial_representation = self.representation
        try:
            self.uuid = self.initial_representation['id']
        except KeyError:
            pass

    @property
    def given_id(self):
        """Get the asked client scope id given by the user.

        :return the asked id given by the user as a name or an uuid.
        :rtype: str
        """
        if self.module.params.get('client_scopes_uuid'):
            return self.module.params.get('client_scopes_uuid')
        return self.module.params.get('client_scopes_name')

    @property
    def representation(self):
        all_client_scopes = get_on_url(
            url=self._get_client_scope_url(),
            restheaders=self.restheaders,
            module=self.module,
            description=self.description,
        )
        if self.uuid:
            return self._clean_representation(all_client_scopes)
        for one_client in all_client_scopes:
            if self.given_id in [one_client['name'], one_client['id']]:
                return self._clean_representation(one_client)
        return {}

    @staticmethod
    def _clean_representation(given_payload):
        if not given_payload:
            return given_payload
        bool_attributes = ['include.in.token.scope', 'display.on.consent.screen']
        int_attributes = ['gui.order']
        new_attributes = given_payload['attributes']
        for key, value in new_attributes.items():
            if key in bool_attributes:
                new_attributes.update({key: convert_to_bool(value)})
            if key in int_attributes:
                new_attributes.update({key: int(value)})
        return given_payload

    def _get_client_scope_url(self):
        """Create the url in order to get the client scope from the given argument (uuid or name)

        Uuid has priority because you can change the name of a scope get from its uuid.

        :return: the url as string
        :rtype: str
        """
        if self.uuid:
            return CLIENT_SCOPES_BY_UUID_URL.format(
                url=self.module.params.get('auth_keycloak_url'),
                realm=quote(self.module.params.get('realm')),
                client_scopes_uuid=quote(self.uuid),
            )
        return CLIENT_SCOPES_BY_NAME_URL.format(
            url=self.module.params.get('auth_keycloak_url'),
            realm=quote(self.module.params.get('realm')),
        )

    def delete(self):
        delete_on_url(
            self._get_client_scope_url(), self.restheaders, self.module, self.description
        )

    def create(self, check=False):
        self._check_arguments()
        client_scope_payload = self._create_payload()
        if check:
            return client_scope_payload
        post_url = CLIENT_SCOPES_BY_NAME_URL.format(
            url=self.module.params.get('auth_keycloak_url'),
            realm=quote(self.module.params.get('realm')),
        )

        post_on_url(
            post_url, self.restheaders, self.module, self.description, client_scope_payload
        )
        return client_scope_payload

    def _create_payload(self):
        payload = {}
        payload_attributes = {}
        not_client_scope_argument = list(keycloak_argument_spec().keys()) + ['state', 'realm']
        attributes_argument = [
            'include_in_token_scope',
            'gui_order',
            'display_on_consent_screen',
            'consent_screen_text',
        ]

        for key, value in filterfalse(
            lambda kv: kv[1] is None or kv[0] in not_client_scope_argument,
            self.module.params.items(),
        ):
            if key in attributes_argument:
                payload_attributes.update({snake_to_point_case(key): value})
            else:
                if key == 'client_scopes_name':
                    payload.update({'name': value})
                else:
                    payload.update({key: value})
        if payload_attributes:
            payload.update({'attributes': payload_attributes})
        return payload

    def _check_arguments(self):
        if self.initial_representation and 'protocol' in self.initial_representation:
            if self.initial_representation['protocol'] == 'saml' and isinstance(
                self.module.params.get('include_in_token_scope'), bool
            ):
                raise KeycloakError(
                    'include_in_token_scope should not be used whith a saml client scope'
                )
        if self.module.params.get('protocol') == 'saml' and isinstance(
            self.module.params.get('include_in_token_scope'), bool
        ):
            raise KeycloakError(
                'include_in_token_scope should not be used whith a saml client scope'
            )

    def update(self, check=False):
        if not self._arguments_update_representation():
            return {}
        self._check_arguments()
        self._check_existing_name()
        client_scope_payload = self._create_payload()
        if not check:
            put_on_url(
                self._get_client_scope_url(),
                self.restheaders,
                self.module,
                self.description,
                client_scope_payload,
            )
        return client_scope_payload

    def _check_existing_name(self):
        all_name = [
            one_scope['name']
            for one_scope in get_on_url(
                url=CLIENT_SCOPES_BY_NAME_URL.format(
                    url=self.module.params.get('auth_keycloak_url'),
                    realm=quote(self.module.params.get('realm')),
                ),
                restheaders=self.restheaders,
                module=self.module,
                description=self.description,
            )
        ]
        if (
            self.module.params.get('client_scopes_uuid')
            and self.module.params.get('client_scopes_name') in all_name
        ):
            raise KeycloakError(
                'Cannot update {description} with {name} because it already exists'.format(
                    description=self.description, name=self.module.params.get('client_scopes_name')
                )
            )

    def _arguments_update_representation(self):
        payload = self._create_payload()
        payload_diff, _ = recursive_diff(payload, self.initial_representation)
        if not payload_diff:
            return False
        return True


def run_module():
    meta_args = dict(
        realm=dict(type='str', default='master'),
        state=dict(type='str', default='present'),
        client_scopes_name=dict(type='str'),
        client_scopes_uuid=dict(type='str'),
        protocol=dict(type=str, choices=['openid-connect', 'saml']),
        include_in_token_scope=dict(type='bool'),
        gui_order=dict(type='int'),
        description=dict(type='str'),
        display_on_consent_screen=dict(type='bool'),
        consent_screen_text=dict(type='str'),
    )
    argument_spec = keycloak_argument_spec()
    argument_spec.update(meta_args)
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_one_of=[['client_scopes_name', 'client_scopes_uuid']],
    )
    try:
        connection_header = get_token(
            base_url=module.params.get('auth_keycloak_url'),
            validate_certs=module.params.get('validate_certs'),
            auth_realm=module.params.get('auth_realm'),
            client_id=module.params.get('auth_client_id'),
            auth_username=module.params.get('auth_username'),
            auth_password=module.params.get('auth_password'),
            client_secret=module.params.get('auth_client_secret'),
        )
        client_scopes = ClientScopes(module, connection_header)
        result = crud_with_instance(client_scopes, 'client_scopes')
    except KeycloakError as err:
        module.fail_json(msg=str(err), changed=False, client_scopes={})

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
