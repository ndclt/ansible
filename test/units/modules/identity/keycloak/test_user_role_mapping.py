# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)

import pytest

from units.modules.utils import (
    AnsibleExitJson, AnsibleFailJson, fail_json, exit_json, set_module_args)
from ansible.modules.identity.keycloak import keycloak_link_role_user


def test_state_absent_without_link_should_not_do_something(monkeypatch):
    monkeypatch.setattr(keycloak_link_role_user.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_link_role_user.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'absent',
        'keycloak_username': 'one_user',
        'role_name': 'one_role'
    }

    set_module_args(arguments)
    with pytest.raises(AnsibleExitJson) as exec_trace:
        keycloak_link_role_user.main()
    ansible_exit_json = exec_trace.value.args[0]
    assert ansible_exit_json['msg'] == (
        'Links between one_user and one_role does not exist, doing nothing.')
