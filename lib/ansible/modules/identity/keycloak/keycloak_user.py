#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Terry Jones <terry.jones@example.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: keycloak_username

short_description: Allows administration of Keycloak users via Keycloak API 

version_added: "2.8"

description:
    - "This is my longer description explaining my sample module"

options:
    name:
        description:
            - This is the message to send to the sample module
        required: true
    new:
        description:
            - Control to demo if the result of this module is changed or not
        required: false
    keycloak_attributes:
        description:
            – a dictionary with the key and the value to put in keycloak. 
            Keycloak will always return the value in a list. For example, 
            if you send {'a key': 'some value'} when updated, the attributes 
            will be returned as following {'a key': ['some value']}. Keys and 
            values are converted into string.
        required: false

extends_documentation_fragment:
    - keycloak

author:
    - Nicolas Duclert (@ndclt)
'''

EXAMPLES = '''
# Pass in a message
- name: Test with a message
  my_new_test_module:
    name: hello world

# pass in a message and have changed true
- name: Test with a message and changed output
  my_new_test_module:
    name: hello world
    new: true

# fail the module
- name: Test failure of the module
  my_new_test_module:
    name: fail me
'''

RETURN = '''
original_message:
    description: The original name param that was passed in
    type: str
message:
    description: The output message that the sample module generates
'''

from ansible.module_utils.keycloak import KeycloakAPI, camel, keycloak_argument_spec
from ansible.module_utils.basic import AnsibleModule


AUTHORIZED_REQUIRED_ACTIONS = [
    'CONFIGURE_TOPT', 'UPDATE_PASSWORD', 'UPDATE_PROFILE', 'VERIFY_EMAIL']
# is this compatible with native string stategy?
AUTHORIZED_ATTRIBUTE_VALUE_TYPE = (str, int, float, bool)


def sanitize_user_representation(user_representation):
    """ Removes probably sensitive details from a user representation

    :param userrep: the userrep dict to be sanitized
    :return: sanitized userrep dict
    """
    result = user_representation.copy()
    if 'credentials' in result:
        # check if this value are to sanitize
        for credential_key in ['hashedSaltedValue', 'salt']:
            if credential_key in result['credentials']:
                result['credentials'][credential_key] = 'no_log'
    return result


def run_module():
    argument_spec = keycloak_argument_spec()
    meta_args = dict(
        state=dict(default='present', choices=['present', 'absent']),
        realm=dict(default='master'),

        keycloak_username=dict(type='str'),
        id=dict(type='str'),

        email_verified=dict(type='bool'),
        enabled=dict(type='bool'),
        keycloak_attributes=dict(type='dict'),
        email=dict(type='str'),
        required_actions=dict(type='list')
    )

    argument_spec.update(meta_args)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_one_of=([['keycloak_username', 'id']]),
                           mutually_exclusive=[['keycloak_username', 'id']]
                           )

    realm = module.params.get('realm')
    state = module.params.get('state')
    given_user_id = {'name': module.params.get('keycloak_username')}
    if not given_user_id['name']:
        given_user_id.update({'id': module.params.get('id')})
        given_user_id.pop('name')

    if not attributes_format_is_correct(module.params.get('keycloak_attributes')):
        module.fail_json(msg=(
            'Attributes are not in the correct format. Should be a dictionary with '
            'one value per key as string, integer and boolean'))

    if not required_actions_are_in_authorized_list(module.params.get('required_actions')):
        module.fail_json(msg=(
            'Required actions can only have the following values: {0}'.format(
                ', '.join(AUTHORIZED_REQUIRED_ACTIONS))))

    kc = KeycloakAPI(module)
    before_user = get_initial_user(given_user_id, kc, realm)

    changeset, result, updated_user = create_result(before_user, module)

    # If the user does not exist yet, before_user is still empty
    if before_user == dict():
        if state == 'absent':
            do_nothing_and_exit(module, result)

        create_user(given_user_id, kc, module, realm, result)
    else:
        if state == 'present':
            updating_user(given_user_id, kc, module, realm, result)
        else:
            deleting_user(given_user_id, kc, module, realm, result)


def create_result(before_user, module):
    changeset = create_changeset(module)
    updated_user = before_user.copy()
    updated_user.update(changeset)
    result = dict(changed=False, msg='', diff={}, proposed={}, existing={},
                  end_state={})
    result['proposed'] = changeset
    result['existing'] = before_user
    return changeset, result, updated_user


def create_changeset(module):
    user_params = [
        x for x in module.params
        if x not in list(keycloak_argument_spec().keys()) + ['state', 'realm'] and
        module.params.get(x) is not None]
    changeset = dict()
    for user_param in user_params:
        new_param_value = module.params.get(user_param)

        # some lists in the Keycloak API are sorted, some are not.
        if isinstance(new_param_value, list):
            if user_param in ['attributes']:
                try:
                    new_param_value = sorted(new_param_value)
                except TypeError:
                    pass

        changeset[camel(user_param)] = new_param_value
    return changeset


def get_initial_user(given_user_id, kc, realm):
    if 'name' in given_user_id:
        before_user = kc.get_user_by_name(given_user_id['name'], realm=realm)
    else:
        before_user = kc.get_user_by_id(given_user_id['id'], realm=realm)
    if before_user is None:
        before_user = dict()
    return before_user


def attributes_format_is_correct(given_attributes):
    if not given_attributes:
        return True
    for one_value in given_attributes.values():
        if isinstance(one_value, list):
            if not attribute_as_list_format_is_correct(one_value):
                return False
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


def required_actions_are_in_authorized_list(given_required_actions):
    if not given_required_actions:
        return True
    if isinstance(given_required_actions, list):
        for one_action in given_required_actions:
            if one_action not in AUTHORIZED_REQUIRED_ACTIONS:
                return False
        else:
            return True
    if given_required_actions not in AUTHORIZED_REQUIRED_ACTIONS:
        return False
    return True


def do_nothing_and_exit(module, result):
    if module._diff:
        result['diff'] = dict(before='', after='')
    result['msg'] = 'User does not exist, doing nothing.'
    module.exit_json(**result)


def deleting_user(given_user_id, kc, module, realm, result):
    before_user = result['existing']
    result['proposed'] = {}
    result['changed'] = True
    if module._diff:
        result['diff']['before'] = sanitize_user_representation(
            before_user)
        result['diff']['after'] = ''
    if module.check_mode:
        module.exit_json(**result)
    asked_id = kc.get_user_id(before_user['username'], realm=realm)
    kc.delete_user(asked_id, realm=realm)
    result['proposed'] = dict()
    result['end_state'] = dict()
    result['msg'] = 'User %s has been deleted.' % list(given_user_id.values())[
        0]
    module.exit_json(**result)


def updating_user(given_user_id, kc, module, realm, result):
    changeset = result['proposed']
    before_user = result['existing']
    updated_user = before_user.copy()
    updated_user.update(changeset)
    result['changed'] = True

    if module.check_mode:
        # We can only compare the current user with the proposed updates we have
        if module._diff:
            result['diff'] = dict(
                before=sanitize_user_representation(before_user),
                after=sanitize_user_representation(updated_user))
        result['changed'] = (before_user != updated_user)
        module.exit_json(**result)

    if 'name' in given_user_id.keys():
        asked_id = kc.get_user_id(given_user_id['name'], realm=realm)
    else:
        asked_id = given_user_id['id']

    kc.update_user(asked_id, changeset, realm=realm)
    after_user = kc.get_user_by_id(asked_id, realm=realm)
    if before_user == after_user:
        result['changed'] = False

    if module._diff:
        result['diff'] = dict(
            before=sanitize_user_representation(before_user),
            after=sanitize_user_representation(after_user))

    result['end_state'] = sanitize_user_representation(after_user)
    result['msg'] = 'User %s has been updated.' % list(given_user_id.values())[
        0]
    module.exit_json(**result)


def create_user(given_user_id, kc, module, realm, result):
    user_to_create = result['proposed']
    result['changed'] = True

    if module._diff:
        result['diff'] = dict(before='',
                              after=sanitize_user_representation(user_to_create))
    if module.check_mode:
        module.exit_json(**result)

    response = kc.create_user(user_to_create, realm=realm)
    after_user = kc.get_json_from_url(response.headers.get('Location'))
    result['end_state'] = sanitize_user_representation(after_user)
    result['msg'] = 'User %s has been created.' % given_user_id['name']
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
