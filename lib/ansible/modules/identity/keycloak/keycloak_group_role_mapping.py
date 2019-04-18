#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Nicolas Duclert <nicolas.duclert@metronlab.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = r'''
---
module: keycloak_group_role_mapping

short_description: Allows administration of Keycloak mapping between group and role via Keycloak API

version_added: "2.9"

description:
    - This module allows the administration of Keycloak clients via the Keycloak REST API. It
      requires access to the REST API via OpenID Connect; the user connecting and the client being
      used must have the requisite access rights. In a default Keycloak installation, admin-cli
      and an admin user would work, as would a separate client definition with the scope tailored
      to your needs and a user having the expected roles.
    - The names of module options are snake_cased versions of the camelCase ones found in the
      Keycloak API and its documentation at U(https://www.keycloak.org/docs-api/4.8/rest-api/index.html/).
      Aliases are provided so camelCased versions can be used as well. If they are in conflict
      with ansible names or previous used names, they will be prefixed by "keycloak".
    - The group, role and client should exist before the call to this module. If not,
      a error message will be return.

options:
    state:
        description:
            - State of the mapping
            - On C(present), the mapping between role and group will be created if it not exists.
            - On C(absent), the mapping between role and group will be removed if it exists
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

    role_name:
        description:
            - Name of the role
            - This parameter is mutually exclusive with role_id and one of
              them is required by the module.
        aliases: [ roleName ]
        type: str

    role_id:
        description:
            - Id (as a uuid) of the role
            - This parameter is mutually exclusive with role_name and one of
              them is required by the module.
        aliases: [ roleId ]
        type: str

    client_id:
        description:
            - Client id of client where the given role will be search. This is
              usually an alphanumeric name chosen by you.
        type: str
        aliases: [ clientId ]

extends_documentation_fragment:
    - keycloak

author:
    - Nicolas Duclert (@ndclt) <nicolas.duclert@metronlab.com>
'''

EXAMPLES = r'''
- name: create the mapping if it does not exist
  keycloak_group_role_mapping:
    auth_client_id: admin-cli
    auth_keycloak_url: http://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    realm: master
    group_name: one_group
    role_name: one_role
- name delete the mapping if it exists
  keycloak_group_role_mapping:
    auth_client_id: admin-cli
    auth_keycloak_url: http://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    realm: master
    state: absent
    group_name: one_group
    role_name: one_role
'''

RETURN = r'''
msg:
  description: Message as to what action was taken
  returned: always
  type: str
  sample: "Link between one_group and one_role created."

changed:
  description: whether the state of the keycloak configuration change
  returned: always
  type: bool

roles_in_group:
  description: the mapped role if it exists.
  returned: always
  type: dict
  sample: {
    'name': 'already_link_role',
    'id': 'ffffffff-1111-1111-1111-111111111111',
    'description': 'showing why this role exists',
  }
'''

from ansible.module_utils.basic import AnsibleModule

from ansible.module_utils._text import to_text
from ansible.module_utils.keycloak import KeycloakAPI, keycloak_argument_spec


def run_module():
    argument_spec = keycloak_argument_spec()
    meta_args = dict(
        state=dict(type='str', default='present',
                   choices=['present', 'absent']),
        realm=dict(type='str', default='master'),
        group_name=dict(type='str', aliases=['groupName']),
        group_id=dict(type='str', aliases=['groupId']),
        role_name=dict(type='str', aliases=['roleName']),
        role_id=dict(type='str', aliases=['roleId']),
        client_id=dict(type='str', aliases=['clientId'], required=False),
    )

    argument_spec.update(meta_args)

    # The id of the role is unique in keycloak and if it is given the
    # client_id is not used. In order to avoid confusion, I set a mutual
    # exclusion.
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_one_of=[
            ['group_name', 'group_id'],
            ['role_name', 'role_id'],
        ],
        mutually_exclusive=[
            ['group_name', 'groupd_id'],
            ['id', 'client_id'],
            ['role_name', 'role_id'],
        ],
    )
    realm = module.params.get('realm')
    state = module.params.get('state')
    result = {}
    kc = KeycloakAPI(module)

    given_role_id = {'name': module.params.get('role_name')}
    if not given_role_id['name']:
        given_role_id.update({'uuid': module.params.get('role_id')})
        given_role_id.pop('name')
    client_id = module.params.get('client_id')

    group_name = module.params.get('group_name')
    if group_name:
        existing_group = kc.get_group_by_name(group_name, realm)
        given_group_id = group_name
    else:
        group_uuid = module.params.get('group_id')
        existing_group = kc.get_group_by_groupid(group_uuid, realm)
        given_group_id = group_uuid
    try:
        group_uuid = existing_group['id']
    except TypeError:
        module.fail_json(msg='group {} not found.'.format(given_group_id))

    if client_id:
        client_uuid = kc.get_client_id(client_id, realm)
        if not client_uuid:
            module.fail_json(msg='client {} not found.'.format(client_id))
        existing_roles = kc.get_client_roles_of_group(group_uuid, client_uuid, realm)
    else:
        client_uuid = None
        existing_roles = kc.get_realm_roles_of_group(group_uuid, realm)
    existing_role_uuid = [role['id'] for role in existing_roles]

    existing_role = kc.get_role(given_role_id, realm, client_uuid=client_uuid)
    try:
        role_uuid = existing_role['id']
    except TypeError:
        if client_id:
            module.fail_json(msg='role {} not found in {}.'.format(
                list(given_role_id.values())[0], client_id))
        module.fail_json(msg='role {} not found.'.format(
            list(given_role_id.values())[0]))

    if state == 'absent':
        if role_uuid not in existing_role_uuid:
            if client_id:
                result['msg'] = to_text(
                    'Links between {group_id} and {role_id} in {client_id} does_not_exist, '
                    'doing nothing.'.format(
                        group_id=given_group_id,
                        role_id=list(given_role_id.values())[0],
                        client_id=client_id
                    ))
            else:
                result['msg'] = to_text(
                    'Links between {group_id} and {role_id} does not exist, doing nothing.'.format(
                        group_id=given_group_id,
                        role_id=list(given_role_id.values())[0]
                    )
                )
            result['changed'] = False
        else:
            kc.delete_link_between_group_and_role(group_uuid, existing_role, client_uuid, realm)
            if client_id:
                result['msg'] = 'Links between {group_id} and {role_id} in {client_id} deleted.'.format(
                    group_id=given_group_id,
                    role_id=list(given_role_id.values())[0],
                    client_id=client_id
                )
            else:
                result['msg'] = 'Links between {group_id} and {role_id} deleted.'.format(
                    group_id=given_group_id,
                    role_id=list(given_role_id.values())[0],
                )
            result['changed'] = True
        result['roles_in_group'] = {}
    else:
        if role_uuid not in existing_role_uuid:
            kc.create_link_between_group_and_role(group_uuid, existing_role, client_uuid, realm)
            if client_uuid:
                result['msg'] = to_text('Link between {} and {} in {} created.'.format(
                    given_group_id,
                    list(given_role_id.values())[0],
                    client_id,
                ))
                updated_roles = kc.get_client_roles_of_group(group_uuid, client_uuid, realm)
            else:
                result['msg'] = to_text('Link between {} and {} created.'.format(
                    given_group_id,
                    list(given_role_id.values())[0],
                ))
                updated_roles = kc.get_realm_roles_of_group(group_uuid, realm)
            result['changed'] = True
            for role in updated_roles:
                if role['id'] == role_uuid:
                    result['roles_in_group'] = role
        else:
            if client_id:
                result['msg'] = 'Links between {} and {} in {} exists, doing nothing.'.format(
                    given_group_id,
                    list(given_role_id.values())[0],
                    client_id,
                )
            else:
                result['msg'] = 'Links between {} and {} exists, doing nothing.'.format(
                    given_group_id,
                    list(given_role_id.values())[0],
                )
            result['changed'] = False
            result['roles_in_group'] = existing_role

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
