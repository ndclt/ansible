# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)

import pytest

from units.modules.utils import (
    AnsibleExitJson, AnsibleFailJson, fail_json, exit_json, set_module_args)
from ansible.modules.identity.keycloak import keycloak_link_group_role


@pytest.mark.parametrize('extra_arguments, waited_message', [
    ({'role_name': 'one_role'},
     'Links between one_group and one_role does not exist, doing nothing.'),
    ({'role_name': 'role_in_client', 'client_id': 'one_client'},
     'Links between one_group and role_in_client in one_client does_not_exist, doing nothing.')
], ids=['role in realm master', 'role in client'])
def test_state_absent_without_link_should_not_do_something(monkeypatch, extra_arguments, waited_message):
    monkeypatch.setattr(keycloak_link_group_role.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_link_group_role.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'absent',
        'group_name': 'one_group',
    }
    arguments.update(extra_arguments)

    set_module_args(arguments)
    with pytest.raises(AnsibleExitJson) as exec_trace:
        keycloak_link_group_role.main()
    ansible_exit_json = exec_trace.value.args[0]
    assert ansible_exit_json['msg'] == waited_message
    assert ansible_exit_json['roles_in_group'] == {}


@pytest.mark.parametrize('extra_arguments, waited_message', [
    ({'group_name': 'to_link', 'role_name': 'one_role'}, 'Link between to_link and one_role created.'),
    ({'group_name': 'to_link', 'role_name': 'role_to_link_in_client', 'client_id': 'one_client'},
     'Link between to_link and role_to_link_in_client in one_client created.'),
    ({'group_id': 'b180d727-3e8b-476c-95e2-345edd96d853', 'role_id': '7c300837-8221-4196-9e02-1f183bfd1882'},
     'Link between b180d727-3e8b-476c-95e2-345edd96d853 and 7c300837-8221-4196-9e02-1f183bfd1882 created.')
], ids=['with name in realm', 'with name one client', 'with uuid for groups and roles'])
def test_state_present_without_link_should_create_link(monkeypatch, extra_arguments, waited_message):
    monkeypatch.setattr(keycloak_link_group_role.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_link_group_role.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'present',
    }
    arguments.update(extra_arguments)
    set_module_args(arguments)
    with pytest.raises(AnsibleExitJson) as exec_trace:
        keycloak_link_group_role.main()
    ansible_exit_json = exec_trace.value.args[0]
    assert ansible_exit_json['msg'] == waited_message
    if 'role_name' in extra_arguments:
        assert ansible_exit_json['roles_in_group']['name'] == extra_arguments['role_name']
    else:
        assert ansible_exit_json['roles_in_group']['id'] == extra_arguments['role_id']


@pytest.mark.parametrize('extra_arguments, waited_message', [
    ({'group_name': 'one_group', 'role_name': 'already_link_role'},
     'Links between one_group and already_link_role exists, doing nothing.'),
    ({'group_name': 'one_group', 'role_name': 'already_link_role', 'client_id': 'one_client'},
     'Links between one_group and already_link_role in one_client exists, doing nothing.')
], ids=['role in master', 'role in client'])
def test_state_present_with_link_should_no_do_something(monkeypatch, extra_arguments, waited_message):
    monkeypatch.setattr(keycloak_link_group_role.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_link_group_role.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'present',
    }
    arguments.update(extra_arguments)
    set_module_args(arguments)
    with pytest.raises(AnsibleExitJson) as exec_trace:
        keycloak_link_group_role.main()
    ansible_exit_json = exec_trace.value.args[0]
    assert ansible_exit_json['msg'] == waited_message
    assert ansible_exit_json['roles_in_group']['name'] == extra_arguments['role_name']
