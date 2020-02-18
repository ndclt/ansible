#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Nicolas Duclert <nicolas.duclert@metronlab.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type
ANSIBLE_METADATA = {'metadata_version': '1.1', 'status': ['preview'], 'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: keycloak_role

short_description: Allows administration of Keycloak composite roles via Keycloak API

version_added: "2.10"

description:
    - This module allows the administration of Keycloak roles via the Keycloak REST API. It
      requires access to the REST API via OpenID Connect; the user connecting and the client being
      used must have the requisite access rights. In a default Keycloak installation, admin-cli
      and an admin user would work, as would a separate client definition with the scope tailored
      to your needs and a user having the expected roles.
    - The names of module options are snake_cased versions of the camelCase ones found in the
      Keycloak API and its documentation at U(https://www.keycloak.org/docs-api/4.8/rest-api/index.html/).
      Aliases are provided so camelCased versions can be used as well. If they are in conflict
      with ansible names or previous used names, they will be prefixed by "keycloak".
    - This module add or removed composite from realm or client in a given role.

options:
    state:
      description:
        - State of the composite role.
        - On C(present), the composite role will be added to the role.
        - On C(absent), the composite role will be removed from role.
      type: str
      choices: [present, absent]
      default: present

    realm:
      description:
        - The realm where the roles resides
      type: str
      default: master
    
    name:
      description:
        - the name of the role to modify.
        - I(name) and I(id) are mutually exclusive.
        - the role must exist before this call.
      type: str

    id:
      description:
        - the id (generally an uuid) of the role to modify.
        - I(name) and I(id) are mutually exclusive.
        - I(id) and I(client_id) are mutually exclusive.
        - the role must exist before this call.
      type: str

    client_id:
      description:
        - client id of client where the role resides. This is usually an alphanumeric name 
        chosen by you.
        - the client must exist before this call.
        - I(id) and I(client_id) are mutually exclusive.
      type: str
      aliases: [ clientId ]

    composites:
      description:
        - a list of composite roles to modify.
        - each role is described by its name, id and can reside in the current realm or a client.
        - the name or id follows the same rules than described in I(id), I(client_id) and I(name)
      type: list
      required: true 
'''

EXAMPLES = r'''
- name: add composite role
  keycloak_compose_role:
    auth_client_id: admin-cli
    auth_keycloak_url: "{{ auth_url }}"
    auth_username: "{{ auth_username }}"
    auth_password: "{{ auth_password }}"
    auth_realm: master
    realm: master
    state: present
    name: role1_in_master
    composites:
      - name: to_link
      - name: role1_in_one_client
        client_id: one_client
- name: remove composite role
  keycloak_compose_role:
    auth_client_id: admin-cli
    auth_keycloak_url: "{{ auth_url }}"
    auth_username: "{{ auth_username }}"
    auth_password: "{{ auth_password }}"
    auth_realm: master
    realm: master
    state: absent
    name: role1_in_master
    composites:
      - name: to_link
      - name: role1_in_one_client
        client_id: one_client
'''

RETURN = r'''
msg:
  description: Message as to what action was taken
  returned: always
  type: str
  sample: "role1_in_one_client (one_client) and to_link are already composite of role role1_in_master"
changed:
  description: whether the state of the keycloak configuration change
  returned: always
  type: bool
keycloak_compose_role:
  role:
    description: the role given id (name or id)
    returned: always
    type: str
  composites:
    description: the modified composites in a key describing the action (added, removed) or empty if nothing was modified
    returned: always
    type: dict 
  sample: {
    'role': 'role1_in_master',
    'composites': {
      'removed': [
        {'name': 'to_link'},
        {'name': 'role1_in_one_client', 'client_id': 'one_client'},
      ]
    },
  }
'''

from itertools import chain
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible.module_utils.common.validation import check_required_one_of, check_mutually_exclusive
from ansible.module_utils.identity.keycloak.keycloak import (
    keycloak_argument_spec,
    get_token,
    KeycloakError,
    KeycloakAPI,
    call_with_payload_on_url,
    get_on_url,
)

COMPOSITE_ADDRESS = '{url}/admin/realms/{realm}/roles-by-id/{role_id}/composites'
REALM_COMPOSITE_ADDRESS = '{url}/admin/realms/{realm}/roles-by-id/{role_id}/composites/realm'
CLIENT_COMPOSITE_ADDRESS = (
    '{url}/admin/realms/{realm}/roles-by-id/{role_id}/composites/clients/{client_id}'
)


class RoleComposer(object):
    def __init__(self, module, connection_header):
        self._check_composites(module)
        self.module = module
        self.restheaders = connection_header
        self._keycloak_api = KeycloakAPI(module, connection_header)
        self._role = self._get_role(
            {
                'name': module.params.get('name'),
                'id': module.params.get('id'),
                'client': module.params.get('client_id'),
            },
            module.params.get('realm'),
            self._keycloak_api,
        )
        self._composites = [
            {
                'role': self._get_role(
                    {
                        'name': one_parameter.get('name'),
                        'id': one_parameter.get('id'),
                        'client': one_parameter.get('client_id'),
                    },
                    module.params.get('realm'),
                    self._keycloak_api,
                ),
                'client_id': one_parameter.get('client_id'),
            }
            for one_parameter in module.params['composites']
        ]

    @staticmethod
    def _given_id(role):
        if role.get('name') is not None:
            return role.get('name')
        return role.get('id')

    @property
    def given_id(self):
        return self._given_id(self._role)

    @property
    def need_update(self):
        all_client_ids = self._keycloak_api.get_clients(realm=self.module.params.get('realm'))
        all_composites = [
            get_on_url(
                url=REALM_COMPOSITE_ADDRESS.format(
                    url=self.module.params.get('auth_keycloak_url'),
                    realm=self.module.params.get('realm'),
                    role_id=self._role['id'],
                ),
                restheaders=self.restheaders,
                module=self.module,
                description='composite roles',
            )
        ]
        for one_client in all_client_ids:
            all_composites.append(
                get_on_url(
                    url=CLIENT_COMPOSITE_ADDRESS.format(
                        url=self.module.params.get('auth_keycloak_url'),
                        realm=self.module.params.get('realm'),
                        role_id=self._role['id'],
                        client_id=one_client['id'],
                    ),
                    restheaders=self.restheaders,
                    module=self.module,
                    description='composite roles',
                )
            )
        all_composites = list(chain.from_iterable(all_composites))
        existing_composites = []
        for one_composite in self._composites:
            composite_to_compare = one_composite['role']
            composite_to_compare.pop('attributes')
            if composite_to_compare in all_composites:
                existing_composites.append(one_composite)
        if self.module.params.get('state') == 'present':
            if existing_composites == self._composites:
                return False
            else:
                return True
        else:
            if existing_composites:
                return True
            else:
                return False

    @staticmethod
    def _check_composites(module):
        for one_parameter in module.params['composites']:
            if not one_parameter:
                one_parameter.update({'fake_key': ''})
            try:
                check_required_one_of([['id', 'name']], one_parameter)
                check_mutually_exclusive([['name', 'id'], ['id', 'client_id']], one_parameter)
            except TypeError as err:
                module.fail_json(msg=to_native(err), changed=False, compose_role={})

    @staticmethod
    def _get_role(role_identifier, realm, keycloak_api):
        """

        :param role_identifier: argument given by the user in order to get the role, it has tree
        keys: name, id, client
        :return:
        """

        if role_identifier['name'] is not None:
            if role_identifier['client']:
                client_uuid = keycloak_api.get_client_id(role_identifier['client'], realm)
            else:
                client_uuid = None
            return keycloak_api.get_role(
                role_id={'name': role_identifier['name']}, realm=realm, client_uuid=client_uuid
            )
        return keycloak_api.get_role(role_id={'id': role_identifier['id']}, realm=realm)

    def update(self):
        if self.module.params.get('state') == 'present':
            method = 'POST'
        else:
            method = 'DELETE'
        for one_role in self._composites:
            url = COMPOSITE_ADDRESS.format(
                url=self.module.params.get('auth_keycloak_url'),
                realm=self.module.params.get('realm'),
                role_id=self._role['id'],
            )
            call_with_payload_on_url(
                url=url,
                restheaders=self.restheaders,
                module=self.module,
                description='composite {composite} of {role}'.format(
                    composite=self._given_id(one_role['role']),
                    role=self._given_id(self.module.params),
                ),
                method=method,
                representation=[one_role['role']],
            )

    @property
    def composite_names(self):
        to_join = []
        for one_role in self.module.params.get('composites'):
            if one_role.get('client_id') is not None:
                to_join.append(
                    '{role_name} ({client_id})'.format(
                        role_name=one_role.get('name'), client_id=one_role.get('client_id')
                    )
                )
            else:
                to_join.append(one_role.get('name'))
        return ', '.join(to_join)


def run_module():
    argument_spec = keycloak_argument_spec()
    meta_args = dict(
        state=dict(type='str', default='present', choices=['present', 'absent']),
        realm=dict(type='str', default='master'),
        name=dict(type='str'),
        id=dict(type='str'),
        client_id=dict(type='str', aliases=['clientId'], required=False),
        composites=dict(type='list', required=True),
    )
    argument_spec.update(meta_args)

    # The id of the role is unique in keycloak and if it is given the
    # client_id is not used. In order to avoid confusion, I set a mutual
    # exclusion.
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_one_of=([['name', 'id']]),
        mutually_exclusive=([['name', 'id'], ['id', 'client_id']]),
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
    except KeycloakError as e:
        module.fail_json(msg=str(e))
    role_composer = RoleComposer(module, connection_header)
    if module.params.get('state') == 'present':
        if role_composer.need_update:
            if not module.check_mode:
                role_composer.update()
            module.exit_json(
                msg='{composites} added to composite role {role}'.format(
                    composites=role_composer.composite_names, role=role_composer.given_id
                ),
                changed=True,
                keycloak_compose_role={
                    'role': role_composer.given_id,
                    'composites': {'added': module.params.get('composites')},
                },
            )
        else:
            module.exit_json(
                msg='{composites} are already composite of role {role}'.format(
                    composites=role_composer.composite_names, role=role_composer.given_id
                ),
                changed=False,
                keycloak_compose_role={'role': role_composer.given_id, 'composites': {}},
            )
    else:
        if role_composer.need_update:
            if not module.check_mode:
                role_composer.update()
            module.exit_json(
                msg='{composites} removed from composite role {role}'.format(
                    composites=role_composer.composite_names, role=role_composer.given_id
                ),
                changed=True,
                keycloak_compose_role={
                    'role': role_composer.given_id,
                    'composites': {'removed': module.params.get('composites')},
                },
            )
        else:
            module.exit_json(
                msg='{composites} are not composite of role {role}'.format(
                    composites=role_composer.composite_names, role=role_composer.given_id
                ),
                changed=False,
                keycloak_compose_role={'role': role_composer.given_id, 'composites': {}},
            )


def main():
    run_module()


if __name__ == '__main__':
    main()
