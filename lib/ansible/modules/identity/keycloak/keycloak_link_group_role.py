#!/usr/bin/python
# -*- coding: utf-8 -*-

from ansible.module_utils.basic import AnsibleModule

from ansible.module_utils._text import to_text
from ansible.module_utils.keycloak import KeycloakAPI, keycloak_argument_spec


def run_module():
    argument_spec = keycloak_argument_spec()
    meta_args = dict(
        state=dict(type='str', default='present',
                   choices=['present', 'absent']),
        realm=dict(type='str', default='master'),
        group_name=dict(type='str', required=False),
        group_id=dict(type='str', required=False),
        client_id=dict(type='str', aliases=['clientId'], required=False),
        role_name=dict(type='str', aliases=['roleName']),
        role_id=dict(type='str', aliases=['roleId']),
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
        group_uuid = existing_group['id']
        given_group_id = group_name
    else:
        group_uuid = module.params.get('group_id')
        given_group_id = group_uuid

    if client_id:
        client_uuid = kc.get_client_id(client_id, realm)
        existing_roles = kc.get_client_roles_of_group(group_uuid, client_uuid, realm)
    else:
        client_uuid = None
        existing_roles = kc.get_realm_roles_of_group(group_uuid, realm)
    existing_role_uuid = [role['id'] for role in existing_roles]

    role = kc.get_role(given_role_id, realm, client_uuid=client_uuid)
    role_uuid = role['id']

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
            result['roles_in_group'] = {}
    else:
        if role_uuid not in existing_role_uuid:
            kc.create_link_between_group_and_role(group_uuid, role, client_uuid, realm)
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
            for role in updated_roles:
                if role['id'] == role_uuid:
                    result['roles_in_group'] = role
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
