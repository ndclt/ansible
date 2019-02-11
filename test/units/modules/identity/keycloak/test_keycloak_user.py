from __future__ import (absolute_import, division, print_function)

import pytest

from ansible.modules.identity.keycloak import keycloak_user
from units.modules.utils import (
    AnsibleExitJson, AnsibleFailJson, fail_json, exit_json, set_module_args, to_bytes)
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


LIST_USER_RESPONSE_ADMIN_ONLY = r"""[
  {
    "id": "882ddb5e-51d0-4aa9-8cb7-556f53e62e90",
    "createdTimestamp": 1549805949269,
    "username": "test_admin",
    "enabled": true,
    "totp": false,
    "emailVerified": false,
    "disableableCredentialTypes": [
      "password"
    ],
    "requiredActions": [],
    "notBefore": 0,
    "access": {
      "manageGroupMembership": true,
      "view": true,
      "mapRoles": true,
      "impersonate": true,
      "manage": true
    }
  }
]"""


RESPONSE_DICT = {
    'http://keycloak.url/auth/realms/master/protocol/openid-connect/token': TextIOWrapper(
        BytesIO(b'{"access_token": "a long token"}'), encoding='utf8'),
    'http://keycloak.url/auth/admin/realms/master/users': TextIOWrapper(
        BytesIO(to_bytes(LIST_USER_RESPONSE_ADMIN_ONLY)), encoding='utf8')
}


def mocked_requests_get(*args, **kwargs):
    url = args[0]
    return RESPONSE_DICT.get(url, None)


def test_state_absent_should_not_create_absent_user(monkeypatch, open_url_mock):
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
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == 'User does not exist, doing nothing.'


def test_state_present_should_create_absent_user(monkeypatch, open_url_mock):
    monkeypatch.setattr(keycloak_user.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_user.AnsibleModule, 'fail_json', fail_json)
    set_module_args(
        {
            'auth_keycloak_url': 'http://keycloak.url/auth',
            'auth_username': 'test_admin',
            'auth_password': 'admin_password',
            'auth_realm': 'master',
            'keycloak_username': 'to_add_user',
            'state': 'present'
        })
    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_user.main()
    ansible_exit_json = exec_error.value.args[0]
    # open_url_mock.mock_calls
    assert ansible_exit_json['msg'] == 'User to_add_user has been created'
