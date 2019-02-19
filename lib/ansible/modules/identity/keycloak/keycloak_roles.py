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

DOCUMENTATION = '''
'''

from ansible.module_utils.keycloak import KeycloakAPI, camel, keycloak_argument_spec
from ansible.module_utils.basic import AnsibleModule


def run_module():
    argument_spec = keycloak_argument_spec()
    meta_args = dict(
        state=dict(type='str', default='present', choices=['present', 'absent']),
        realm=dict(type='str', default='master'),
        name=dict(type='str')
    )

    argument_spec.update(meta_args)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           )
    realm = module.params.get('realm')
    state = module.params.get('state')
    given_role_id = {'name': module.params.get('name')}
    if not given_role_id['name']:
        given_role_id.update({'id': module.params.get('role_id')})
        given_role_id.pop('name')

    kc = KeycloakAPI(module)
    before_role = get_initial_role(given_role_id, kc, realm)
    result = create_result(before_role, module)

    if before_role == dict():
        if state == 'absent':
            do_nothing_and_exit(kc, result)


def get_initial_role(given_user_id, kc, realm):
    if 'name' in given_user_id:
        before_user = kc.get_role_by_name(given_user_id['name'], realm=realm)
    else:
        before_user = kc.get_role_by_id(given_user_id['id'], realm=realm)
    if before_user is None:
        before_user = dict()
    return before_user


def create_result(before_user, module):
    changeset = create_changeset(module)
    result = dict(changed=False, msg='', diff={}, proposed={}, existing={},
                  end_state={})
    result['proposed'] = changeset
    result['existing'] = before_user
    return result


def create_changeset(module):
    role_params = [
        x for x in module.params
        if x not in list(keycloak_argument_spec().keys()) + ['state', 'realm'] and
        module.params.get(x) is not None]
    changeset = dict()

    for role_param in role_params:
        new_param_value = module.params.get(role_param)

        # some lists in the Keycloak API are sorted, some are not.
        if isinstance(new_param_value, list):
            if role_param in ['attributes']:
                try:
                    new_param_value = sorted(new_param_value)
                except TypeError:
                    pass

        changeset[camel(role_param)] = new_param_value
    return changeset


def do_nothing_and_exit(kc, result):
    module = kc.module
    if module._diff:
        result['diff'] = dict(before='', after='')
    result['msg'] = 'Role does not exist, doing nothing.'
    module.exit_json(**result)


if __name__ == '__main__':
    run_module()

