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
        keycloak_username=dict(type='str', aliases=['keycloakUsername']),
        user_id=dict(type='str', aliases=['userId']),
        group_name=dict(type='str'),
        group_id=dict(type='str'),
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
            ['keycloak_username', 'user_id'],
            ['group_name', 'group_id'],
            ['role_name', 'role_id'],
        ],
        mutually_exclusive=[
            ['keycloak_username', 'user_id'],
            ['group_name', 'groupd_id'],
            ['id', 'client_id'],
            ['role_name', 'role_id'],
        ],
    )
    realm = module.params.get('realm')
    state = module.params.get('state')
    given_user_id = {'name': module.params.get('keycloak_username')}
    if not given_user_id['name']:
        given_user_id.update({'id': module.params.get('user_id')})
        given_user_id.pop('name')
    else:
        given_user_id.update({'name': given_user_id['name'].lower()})
    given_role_id = {'name': module.params.get('name')}
    if not given_role_id['name']:
        given_role_id.update({'uuid': module.params.get('id')})
        given_role_id.pop('name')
    client_id = module.params.get('client_id')
    kc = KeycloakAPI(module)
    role_uuid = kc.get_role_id(given_role_id, realm, client_uuid=client_id)


def main():
    run_module()


if __name__ == '__main__':
    main()
