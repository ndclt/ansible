from __future__ import (absolute_import, division, print_function)

import pytest

from ansible.modules.identity.keycloak import keycloak_user
from units.modules.utils import (
    AnsibleExitJson, AnsibleFailJson, fail_json, exit_json, set_module_args, to_bytes)
from ansible.module_utils.six import BytesIO
from io import TextIOWrapper


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

CREATED_USER_RESPONSE = """{
    "id": "992ddb5e-51d0-4aa9-8cb7-556f53e62e91",
    "createdTimestamp": 1549805950370,
    "username": "to_add_user",
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
"""


def create_wrapper(text_as_string):
    def _create_wrapper():
        return TextIOWrapper(BytesIO(to_bytes(text_as_string)), encoding='utf8')
    return _create_wrapper


@pytest.fixture
def open_url_mock(mocker):
    return mocker.patch(
        'ansible.module_utils.keycloak.open_url',
        side_effect=mocked_requests_get,
        autospec=True
    )


class MockResponse():
    def __init__(self):
        self.headers = {'Location': 'http://keycloak.url/auth/admin/realms/master/users/992ddb5e-51d0-4aa9-8cb7-556f53e62e91'}


RESPONSE_DICT = {
    'http://keycloak.url/auth/realms/master/protocol/openid-connect/token': create_wrapper('{"access_token": "a long token bla"}'),
    'http://keycloak.url/auth/admin/realms/master/users': {
        'GET': create_wrapper(LIST_USER_RESPONSE_ADMIN_ONLY),
        'POST': MockResponse()
    },
    'http://keycloak.url/auth/admin/realms/master/users/992ddb5e-51d0-4aa9-8cb7-556f53e62e91': create_wrapper(
        CREATED_USER_RESPONSE)
}


def mocked_requests_get(*args, **kwargs):
    url = args[0]
    method = kwargs['method']
    future_response = RESPONSE_DICT.get(url, None)
    if isinstance(future_response, dict):
        future_response = future_response[method]
    if callable(future_response):
        return future_response()
    return future_response


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
    assert ansible_exit_json['msg'] == 'User to_add_user has been created.'
