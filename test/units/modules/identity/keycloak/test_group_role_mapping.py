# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)

import pytest

from units.modules.utils import (
    AnsibleExitJson, AnsibleFailJson, fail_json, exit_json, set_module_args)
from ansible.modules.identity.keycloak import keycloak_link_group_role


def test_state_absent_without_link_should_not_do_something(monkeypatch):
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
        'role_name': 'one_role'
    }

    set_module_args(arguments)
    with pytest.raises(AnsibleExitJson) as exec_trace:
        keycloak_link_group_role.main()
    ansible_exit_json = exec_trace.value.args[0]
    assert ansible_exit_json['msg'] == (
        'Links between one_group and one_role does not exist, doing nothing.')
