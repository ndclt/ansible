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
module: keycloak_link_user_to_group

short_description: Allows administration of Keycloak mapping between group and users via Keycloak API

version_added: "2.9"

description:
  - This module allows the administration of link between user and group in Keycloak via the Keycloak REST API. It
    requires access to the REST API via OpenID Connect; the user connecting and the client being
    used must have the requisite access rights. In a default Keycloak installation, admin-cli
    and an admin user would work, as would a separate client definition with the scope tailored
    to your needs and a user having the expected roles.
  - The names of module options are snake_cased versions of the camelCase ones found in the
    Keycloak API and its documentation at U(https://www.keycloak.org/docs-api/4.8/rest-api/index.html/).
    Aliases are provided so camelCased versions can be used as well. If they are in conflict
    with ansible names or previous used names, they will be prefixed by "keycloak".
  - The group and users should exist before the call to this module. If not,
    a error message will be return.

options:
  state:
    description:
      - State of the mapping
      - On C(present), the mapping between user and group will be created if it not exists.
      - On C(absent), the mapping between user and group will be removed if it exists
    type: str
    choices: [ present, absent ]
    default: present
  
  realm:
    description:
      - The realm where the role, group and optionaly client are.
    type: str
    default: master

  group_name:
    description:
      - Name of the group
      - This parameter is mutually exclusive with group_id and one of
        them is required by the module.
    aliases: [ groupName ]
    type: str

  group_id:
    description:
    - Id (as a uuid) of the group
    - This parameter is mutually exclusive with group_name and one of
      them is required by the module.
    aliases: [ groupId ]
    type: str

  user_id:
    description:
      - user_id of client to be worked on. This is usually an UUID. This and I(client_username)
        are mutually exclusive.
    aliases: [ userId ]
    type: str

  keycloak_username:
    description:
      - username of user to be worked on. This and I(user_id) are mutually exclusive.
    aliases: [ keycloakUsername ]
    type: str

extends_documentation_fragment:
    - keycloak
author:
    - Nicolas Duclert (@ndclt) <nicolas.duclert@metronlab.com>
'''

EXAMPLES = r'''
- name: create the mapping if it does not exist
  keycloak_link_user_to_group:
    auth_client_id: admin-cli
    auth_keycloak_url: http://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    realm: master
    group_name: one_group
    keycloak_username: one_role
- name delete the mapping if it exists
  keycloak_link_user_to_group:
    auth_client_id: admin-cli
    auth_keycloak_url: http://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    realm: master
    state: absent
    group_id: bc8e2fc4-741a-47f1-b342-1996eb534404
    user_id: 6970217a-7977-40e8-a96e-49fe57430a4c
'''

RETURN = r'''
msg:
  description: Message as to what action was taken
  returned: always
  type: str
  sample: "Link between one_user and one_group created."
changed:
  description: whether the state of the keycloak configuration change
  returned: always
  type: bool
link_user_to_group:
  description: the given identifier for the group and the user linked or an empty dictionary if the link does not exist at the end of the module.
  returned: always
  type: dict
  sample: {
      'group_name': 'group1',
      'keycloak_username': 'user1'
  }
'''

from ansible.module_utils.identity.keycloak.keycloak import (
    KeycloakAPI,
    keycloak_argument_spec,
    KeycloakAuthorizationHeader,
    get_on_url,
    put_on_url,
    delete_on_url,
)
from ansible.module_utils.basic import AnsibleModule


LIST_GROUP_OF_USER_URL = '{url}/admin/realms/{realm}/users/{id}/groups'
LINK_MODIFICATION_URL = '{url}/admin/realms/{realm}/users/{user_id}/groups/{group_id}'


def get_all_mutually_exclusive_values(module):
    exclusive_arguments = {}
    for one_mutually_exclusive in module.mutually_exclusive:
        for one_argument in one_mutually_exclusive:
            value = module.params.get(one_argument)
            if value:
                exclusive_arguments.update({one_argument: value})
                break
    return exclusive_arguments


class KeycloakLinkUserToGroup(object):
    def __init__(self, module, connection_header):
        self.module = module
        self.restheader = connection_header
        exclusive_arguments = get_all_mutually_exclusive_values(module)
        old_module = KeycloakAPI(module, self.restheader)
        self._group_id, self.given_group = self._get_group_id(
            module, exclusive_arguments, old_module
        )
        self._user_id, self.given_user = self._get_user_id(
            module, exclusive_arguments, old_module
        )
        self._user_groups_id = []
        self._list_group_for_users()

    @staticmethod
    def _get_group_id(module, exclusive_arguments, old_module):
        realm = module.params.get('realm')
        if 'group_name' in list(exclusive_arguments.keys()):
            value = exclusive_arguments['group_name']
            group = old_module.get_group_by_name(value, realm)
        else:
            value = exclusive_arguments['group_id']
            group = old_module.get_group_by_groupid(value, realm)
        try:
            return group['id'], value
        except TypeError:
            module.fail_json(msg='Group %s does not exist' % value)

    @staticmethod
    def _get_user_id(module, exclusive_arguments, old_module):
        realm = module.params.get('realm')
        if 'keycloak_username' in list(exclusive_arguments.keys()):
            value = exclusive_arguments['keycloak_username']
            user = old_module.get_user_by_name(value, realm)
        else:
            value = exclusive_arguments['user_id']
            user = old_module.get_user_by_id(value, realm)
        try:
            return user['id'], value
        except TypeError:
            module.fail_json(msg='User %s does not exist' % value)

    def _list_group_for_users(self):
        url = LIST_GROUP_OF_USER_URL.format(
            url=self.module.params.get('auth_keycloak_url'),
            realm=self.module.params.get('realm'),
            id=self._user_id,
        )
        group_response = get_on_url(
            url=url,
            restheaders=self.restheader,
            module=self.module,
            description='groups of user',
        )
        print(group_response)
        self._user_groups_id = [one_group['id'] for one_group in group_response]

    def are_user_and_group_linked(self):
        if self._group_id in self._user_groups_id:
            return True
        return False

    def create_link(self):
        url = LINK_MODIFICATION_URL.format(
            url=self.module.params.get('auth_keycloak_url'),
            realm=self.module.params.get('realm'),
            user_id=self._user_id,
            group_id=self._group_id,
        )
        description = 'link between {user_name} and {group_name}'.format(
            user_name=self.module.params.get('keycloak_username'),
            group_name=self.module.params.get('group_name'),
        )
        put_on_url(
            url=url,
            restheaders=self.restheader,
            module=self.module,
            description=description,
        )

    def delete_link(self):
        url = LINK_MODIFICATION_URL.format(
            url=self.module.params.get('auth_keycloak_url'),
            realm=self.module.params.get('realm'),
            user_id=self._user_id,
            group_id=self._group_id,
        )
        description = 'link between {user_name} and {group_name}'.format(
            user_name=self.module.params.get('keycloak_username'),
            group_name=self.module.params.get('group_name'),
        )
        delete_on_url(
            url=url,
            restheaders=self.restheader,
            module=self.module,
            description=description,
        )

    def get_link_representation(self):
        link_representation = {}
        exclusive_arguments = get_all_mutually_exclusive_values(self.module)
        if 'group_name' in list(exclusive_arguments.keys()):
            link_representation.update(
                {'group_name': exclusive_arguments['group_name']}
            )
        else:
            link_representation.update({'group_id': exclusive_arguments['group_id']})
        if 'keycloak_username' in list(exclusive_arguments.keys()):
            link_representation.update(
                {'keycloak_username': exclusive_arguments['keycloak_username']}
            )
        else:
            link_representation.update({'user_id': exclusive_arguments['user_id']})
        return link_representation


def run_module():
    argument_spec = keycloak_argument_spec()
    meta_args = dict(
        state=dict(default='present', choices=['present', 'absent']),
        realm=dict(default='master'),
        keycloak_username=dict(type='str', aliases=['keycloakUsername']),
        user_id=dict(type='str', aliases=['userId']),
        group_name=dict(type='str', aliases=['groupName']),
        group_id=dict(type='str', aliases=['groupId']),
    )

    argument_spec.update(meta_args)

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_one_of=[['keycloak_username', 'user_id'], ['group_name', 'group_id']],
        mutually_exclusive=[
            ['keycloak_username', 'user_id'],
            ['group_name', 'group_id'],
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

    link_user_to_group = KeycloakLinkUserToGroup(module, connection_header)
    state = module.params.get('state')
    result = {}

    if not link_user_to_group.are_user_and_group_linked() and state == 'absent':
        result['msg'] = (
            'Link between user {given_user_id} and group {given_group_id} does not exist, nothing to do.'
        ).format(
            given_group_id=link_user_to_group.given_group,
            given_user_id=link_user_to_group.given_user,
        )
        result['changed'] = False
        result['link_user_to_group'] = {}
    elif link_user_to_group.are_user_and_group_linked() and state == 'present':
        result['msg'] = (
            'Link between user {given_user_id} and group {given_group_id} exists, nothing to do.'
        ).format(
            given_group_id=link_user_to_group.given_group,
            given_user_id=link_user_to_group.given_user,
        )
        result['changed'] = False
        result['link_user_to_group'] = link_user_to_group.get_link_representation()
    elif not link_user_to_group.are_user_and_group_linked() and state == 'present':
        if not module.check_mode:
            result['changed'] = True
            link_user_to_group.create_link()
        else:
            result['changed'] = False

        result['link_user_to_group'] = link_user_to_group.get_link_representation()
        result['msg'] = (
            'Link between user {given_user_id} and group {given_group_id} created.'
        ).format(
            given_group_id=link_user_to_group.given_group,
            given_user_id=link_user_to_group.given_user,
        )
    elif link_user_to_group.are_user_and_group_linked() and state == 'absent':
        if not module.check_mode:
            result['changed'] = True
            link_user_to_group.delete_link()
        else:
            result['changed'] = False
        result['link_user_to_group'] = {}
        result['msg'] = (
            'Link between user {given_user_id} and group {given_group_id} deleted.'
        ).format(
            given_group_id=link_user_to_group.given_group,
            given_user_id=link_user_to_group.given_user,
        )
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
