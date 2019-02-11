#!/usr/bin/python

# Copyright: (c) 2018, Terry Jones <terry.jones@example.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

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

        email_verified=dict(type='bool', default=False),
        enabled=dict(type='bool', default=True),
        attributes=dict(type='dict', default={}),
        email=dict(type=str)
    )

    argument_spec.update(meta_args)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_one_of=([['keycloak_username', 'id']]),
                           )
    result = dict(changed=False, msg='', diff={}, proposed={}, existing={}, end_state={})

    user_name = module.params.get('keycloak_username')
    realm = module.params.get('realm')
    state = module.params.get('state')

    given_user_id = module.params.get('keycloak_username')
    if not given_user_id:
        given_user_id = module.params.get('id')

    new_given_user_id = {'name': module.params.get('keycloak_username')}
    if not new_given_user_id['name']:
        new_given_user_id.update({'id': module.params.get('id')})
        new_given_user_id.pop('name')

    user_params = [
        x for x in module.params
        if x not in list(keycloak_argument_spec().keys()) + ['state', 'realm'] and
        module.params.get(x) is not None]

    kc = KeycloakAPI(module)
    if user_name is None:
        asked_id = module.params.get('id')
        before_user = kc.get_user_by_id(asked_id, realm=realm)
    else:
        before_user = kc.get_user_by_name(user_name, realm=realm)
    if before_user is None:
        before_user = dict()

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

    updated_user = before_user.copy()
    updated_user.update(changeset)

    result['proposed'] = changeset
    result['existing'] = before_user

    # If the user does not exist yet, before_user is still empty
    manage_modifications(before_user, new_given_user_id, kc, module, realm, result,
                         state, updated_user)


def manage_modifications(before_user, given_user_id, kc, module, realm, result,
                         state, updated_user):
    if before_user == dict():
        if state == 'absent':
            # do nothing and exit
            if module._diff:
                result['diff'] = dict(before='', after='')
            result['msg'] = 'User does not exist, doing nothing.'
            module.exit_json(**result)

        # create new user
        result['changed'] = True

        if module._diff:
            result['diff'] = dict(before='',
                                  after=sanitize_user_representation(
                                      updated_user))

        if module.check_mode:
            module.exit_json(**result)

        response = kc.create_user(updated_user, realm=realm)
        after_user = kc.get_json_from_url(response.headers.get('Location'))

        result['end_state'] = sanitize_user_representation(after_user)

        result['msg'] = 'User %s has been created.' % given_user_id['name']
        module.exit_json(**result)
    else:
        if state == 'present':
            # update existing user
            result['changed'] = True
            if module.check_mode:
                # We can only compare the current user with the proposed updates we have
                if module._diff:
                    result['diff'] = dict(
                        before=sanitize_user_representation(before_user),
                        after=sanitize_user_representation(updated_user))
                result['changed'] = (before_user != updated_user)

                module.exit_json(**result)
            if given_user_id['name']:
                asked_id = kc.get_user_id(updated_user['username'], realm=realm)
            else:
                asked_id = given_user_id['id']

            kc.update_user(asked_id, updated_user, realm=realm)
            after_user = kc.get_user_by_id(asked_id, realm=realm)
            if before_user == after_user:
                result['changed'] = False
            if module._diff:
                result['diff'] = dict(
                    before=sanitize_user_representation(before_user),
                    after=sanitize_user_representation(after_user))
            result['end_state'] = sanitize_user_representation(after_user)

            result['msg'] = 'User %s has been updated.' % list(given_user_id.values())[0]
            module.exit_json(**result)
        else:
            # Delete existing user
            result['changed'] = True
            if module._diff:
                result['diff']['before'] = sanitize_user_representation(
                    before_user)
                result['diff']['after'] = ''

            if module.check_mode:
                module.exit_json(**result)
            asked_id = kc.get_user_id(updated_user['username'], realm=realm)

            kc.delete_user(asked_id, realm=realm)
            result['proposed'] = dict()
            result['end_state'] = dict()
            result['msg'] = 'User %s has been deleted.' % list(given_user_id.values())[0]
            module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
