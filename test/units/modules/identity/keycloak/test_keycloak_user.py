from __future__ import (absolute_import, division, print_function)

import pytest

from ansible.modules.identity.keycloak import keycloak_user
from units.modules.utils import (
    AnsibleExitJson, AnsibleFailJson, fail_json, exit_json, set_module_args)
from ansible.module_utils.six import BytesIO
from io import TextIOWrapper


@pytest.fixture
def open_url_mock(mocker):
    return mocker.patch(
        'ansible.module_utils.keycloak.open_url',
        # 'ansible.modules.identity.keycloak.open_url',
        side_effect=mocked_requests_get,
        autospec=True
    )


# def get_bin_path(arg, required=False):
#     """Mock AnsibleModule.get_bin_path"""
#     if arg.endswith('my_command'):
#         return '/usr/bin/my_command'
#     else:
#         if required:
#             fail_json(msg='%r not found !' % arg)

def mocked_requests_get(*args, **kwargs):
    if args[0] == 'http://keycloak.url/auth/realms/master/protocol/openid-connect/token':
        return TextIOWrapper(BytesIO(b'{"access_token": "a long token"}'), encoding='utf8')
    else:
        pass


def test_nothing_to_do(monkeypatch, open_url_mock):
    monkeypatch.setattr(keycloak_user.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_user.AnsibleModule, 'fail_json', fail_json)
    set_module_args(
        {
            'auth_keycloak_url': 'http://keycloak.url/auth',
            'auth_username': 'test_admin',
            'auth_password': 'admin_password',
            'auth_realm': 'master',
            'keycloak_username': 'to_not_add_user',
            'state': 'absent'
        })
    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_user.main()
    assert True
