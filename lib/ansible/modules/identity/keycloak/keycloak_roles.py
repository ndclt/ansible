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

from ansible.module_utils._text import to_text
from ansible.module_utils.keycloak import KeycloakAPI, camel, keycloak_argument_spec
from ansible.module_utils.basic import AnsibleModule

AUTHORIZED_ATTRIBUTE_VALUE_TYPE = (str, int, float, bool)


def run_module():
    argument_spec = keycloak_argument_spec()
    meta_args = dict(
        state=dict(type='str', default='present', choices=['present', 'absent']),
        realm=dict(type='str', default='master'),
        name=dict(type='str'),
        id=dict(type='str'),
        client_id=dict(type='str'),
        description=dict(type='str'),
        attributes=dict(type='dict'),
    )

    argument_spec.update(meta_args)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           )
    realm = module.params.get('realm')
    state = module.params.get('state')
    given_role_id = module.params.get('name')
    if not given_role_id:
        given_role_id= module.params.get('id')
    client_id = module.params.get('client_id')

    if not attributes_format_is_correct(module.params.get('attributes')):
        module.fail_json(msg=(
            'Attributes are not in the correct format. Should be a dictionary with '
            'one value per key as string, integer and boolean'))

    kc = KeycloakAPI(module)
    before_role, client_uuid = get_initial_role(given_role_id, kc, realm, client_id)
    result = create_result(before_role, module)

    if before_role == dict():
        if state == 'absent':
            do_nothing_and_exit(kc, result, realm, given_role_id, client_id, client_uuid)
        create_role(kc, result, realm, given_role_id, client_id)
    else:
        if state == 'present':
            updating_user(kc, result, realm, given_role_id, client_uuid)
        else:
            deleting_role(kc, result, realm, given_role_id, client_uuid)


def attributes_format_is_correct(given_attributes):
    if not given_attributes:
        return True
    for one_value in given_attributes.values():
        if isinstance(one_value, list):
            if not attribute_as_list_format_is_correct(one_value):
                return False
            continue
        if isinstance(one_value, dict):
            return False
        if not isinstance(one_value, AUTHORIZED_ATTRIBUTE_VALUE_TYPE):
            return False
    return True


def attribute_as_list_format_is_correct(one_value, first_call=True):
    if isinstance(one_value, list) and first_call:
        if len(one_value) > 1:
            return False
        return attribute_as_list_format_is_correct(one_value[0], False)
    else:
        if not isinstance(one_value, AUTHORIZED_ATTRIBUTE_VALUE_TYPE):
            return False
    return True


def get_initial_role(given_role_id, kc, realm, client_id):
    if client_id:
        client_uuid = kc.get_client_id(client_id, realm)
    else:
        client_uuid = None
    before_role = kc.get_role(given_role_id, realm=realm, client_uuid=client_uuid)
    if before_role is None:
        before_role = dict()
    return before_role, client_uuid


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


def do_nothing_and_exit(kc, result, realm, given_role_id, client_id, client_uuid):
    module = kc.module
    if module._diff:
        result['diff'] = dict(before='', after='')
    if client_id:
        if not client_uuid:
            result['msg'] = (
                'Client %s does not exist in %s, cannot found role %s in it, doing nothing.'
                % (to_text(client_id), realm, to_text(given_role_id)))
        else:
            result['msg'] = (
                'Role %s does not exist in client %s of realm %s, doing nothing.'
                % (to_text(given_role_id), to_text(client_id), to_text(realm)))
    else:
        result['msg'] = ('Role %s does not exist in realm %s, doing nothing.'
                         % (to_text(given_role_id), to_text(realm)))
    module.exit_json(**result)


def create_role(kc, result, realm, given_role_id, client_id):
    if client_id:
        client_uuid = kc.get_client_id(client_id, realm)
    else:
        client_uuid = None
    module = kc.module
    role_to_create = result['proposed']
    result['changed'] = True

    if module._diff:
        result['diff'] = dict(before='',
                              after=role_to_create)
    if module.check_mode:
        module.exit_json(**result)

    response = kc.create_role(role_to_create, realm=realm, client_uuid=client_uuid)
    if 'attributes' in result['proposed']:
        kc.update_role(given_role_id, role_to_create, realm=realm, client_uuid=client_uuid)
    after_user = kc.get_json_from_url(response.headers.get('Location'))
    result['end_state'] = after_user
    result['msg'] = 'Role %s has been created.' % given_role_id
    module.exit_json(**result)


def updating_user(kc, result, realm, given_role_id, client_uuid):
    module = kc.module
    changeset = result['proposed']
    before_role = result['existing']
    updated_role = before_role.copy()
    updated_role.update(changeset)
    result['changed'] = True

    if module.check_mode:
        # We can only compare the current user with the proposed updates we have
        if module._diff:
            result['diff'] = dict(
                before=before_role,
                after=updated_role)
        result['changed'] = (before_role != updated_role)
        module.exit_json(**result)

    kc.update_role(given_role_id, changeset, realm=realm, client_uuid=client_uuid)
    after_role = kc.get_role(given_role_id, realm=realm, client_uuid=client_uuid)
    if before_role == after_role:
        result['changed'] = False

    if module._diff:
        result['diff'] = dict(
            before=before_role,
            after=after_role)

    result['end_state'] = after_role
    result['msg'] = 'Role %s has been updated.' % given_role_id
    module.exit_json(**result)


def deleting_role(kc, result, realm, given_role_id, client_uuid):
    module = kc.module
    result['proposed'] = {}
    result['changed'] = True
    if module._diff:
        result['diff']['before'] = result['existing']
        result['diff']['after'] = ''
    if module.check_mode:
        module.exit_json(**result)
    asked_id = kc.get_role_id(given_role_id, realm, client_uuid)
    kc.delete_role(asked_id, realm=realm)
    result['proposed'] = dict()
    result['end_state'] = dict()
    result['msg'] = 'Role %s has been deleted.' % given_role_id
    module.exit_json(**result)


if __name__ == '__main__':
    run_module()

