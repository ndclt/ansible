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
module: keycloak_user

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


def run_module():
    argument_spec = keycloak_argument_spec()
    meta_args = dict(
        state=dict(default='present', choices=['present', 'absent']),
        realm=dict(default='master'),

        name=dict(type='str'),
        id=dict(type='str')
    )

    argument_spec.update(meta_args)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_one_of=([['name', 'id']]))
    result = dict(changed=False, msg='', diff={}, proposed={}, existing={}, end_state={})

    user_name = module.params.get('name')
    realm = module.params.get('realm')
    state = module.params.get('state')

    user_params = [
        x for x in module.params
        if x not in list(keycloak_argument_spec().keys()) + ['state', 'realm'] and
        module.params.get(x) is not None]

    kc = KeycloakAPI(module)
    if user_name is None:
        asked_id = module.params.get('id')
        before_client = kc.get_user_by_id(asked_id, realm=realm)
    else:
        before_client = kc.get_user_by_name(user_name, realm=realm)
    if before_client is None:
        before_client = dict()

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

    updated_client = before_client.copy()
    updated_client.update(changeset)

    result['proposed'] = changeset
    result['existing'] = before_client

    if module.check_mode:
        return result

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    #result['original_message'] = module.params['name']
    #result['message'] = 'goodbye'

    # use whatever logic you need to determine whether or not this module
    # made any modifications to your target
    #if module.params['new']:
    #    result['changed'] = True

    # during the execution of the module, if there is an exception or a
    # conditional state that effectively causes a failure, run
    # AnsibleModule.fail_json() to pass in the message and the result
    #if module.params['name'] == 'fail me':
    #    module.fail_json(msg='You requested this to fail', **result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
