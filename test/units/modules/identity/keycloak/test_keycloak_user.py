from __future__ import (absolute_import, division, print_function)

import json
from itertools import count

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
  },
  {
    "id": "883eeb5e-51d0-4aa9-8cb7-667f53e62e90",
    "createdTimestamp": 1549806949269,
    "username": "user1",
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
  },
  {
    "id": "994eeb5e-62e1-4bb9-8cb7-667f53e62f01",
    "createdTimestamp": 1549806949269,
    "username": "to_delete",
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

TO_DELETE_USER = """{
    "id": "994eeb5e-62e1-4bb9-8cb7-667f53e62f01",
    "createdTimestamp": 1549806949269,
    "username": "to_delete",
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
  }"""

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

UPDATED_USER = """{
    "id": "883eeb5e-51d0-4aa9-8cb7-667f53e62e90",
    "createdTimestamp": 1549806949269,
    "username": "user1",
    "enabled": true,
    "totp": false,
    "email": "user1@domain.net",
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
  }"""

GET_USER_BY_ID = """{
    "id": "883eeb5e-51d0-4aa9-8cb7-667f53e62e90",
    "createdTimestamp": 1549806949269,
    "username": "user1",
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


@pytest.fixture
def url_mock_keycloak(mocker):
    return mocker.patch(
        'ansible.module_utils.keycloak.open_url',
        side_effect=build_mocked_request(count(), RESPONSE_ADMIN_ONLY),
        autospec=True
    )


def build_mocked_request(get_id_user_count, response_dict):
    def _mocked_requests(*args, **kwargs):
        url = args[0]
        method = kwargs['method']
        future_response = response_dict.get(url, None)
        return get_response(future_response, method, get_id_user_count)
    return _mocked_requests


def get_response(object_with_future_response, method, get_id_call_count):
    if callable(object_with_future_response):
        return object_with_future_response()
    if isinstance(object_with_future_response, dict):
        return get_response(
            object_with_future_response[method], method, get_id_call_count)
    if isinstance(object_with_future_response, list):
        call_number = get_id_call_count.__next__()
        print('call to id number {}'.format(call_number))
        return get_response(
            object_with_future_response[call_number], method, get_id_call_count)
    return object_with_future_response


class CreatedUserMockResponse(object):
    def __init__(self):
        self.headers = {'Location': 'http://keycloak.url/auth/admin/realms/master/users/992ddb5e-51d0-4aa9-8cb7-556f53e62e91'}


def create_wrapper(text_as_string):
    """Allow to mock many times a call to one address.

    Without this function, the TextIOWrapper is empty for the second call.
    """
    def _create_wrapper():
        return TextIOWrapper(BytesIO(to_bytes(text_as_string)), encoding='utf8')
    return _create_wrapper


RESPONSE_ADMIN_ONLY = {
    'http://keycloak.url/auth/realms/master/protocol/openid-connect/token': create_wrapper('{"access_token": "a long token"}'),
    'http://keycloak.url/auth/admin/realms/master/users': {
        'GET': create_wrapper(LIST_USER_RESPONSE_ADMIN_ONLY),
        'POST': CreatedUserMockResponse()
    },
    'http://keycloak.url/auth/admin/realms/master/users/992ddb5e-51d0-4aa9-8cb7-556f53e62e91': create_wrapper(
        CREATED_USER_RESPONSE),
    'http://keycloak.url/auth/admin/realms/master/users/994eeb5e-62e1-4bb9-8cb7-667f53e62f01': {
        'GET': create_wrapper(TO_DELETE_USER),
        'DELETE': None
    }
}


def test_state_absent_should_not_create_absent_user(monkeypatch, url_mock_keycloak):
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


def test_state_present_should_create_absent_user(monkeypatch, url_mock_keycloak):
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


@pytest.mark.parametrize('user_to_delete', [
    {'keycloak_username': 'to_delete'},
    {'id': '994eeb5e-62e1-4bb9-8cb7-667f53e62f01'},
], ids=['with name', 'with id'])
def test_state_absent_should_delete_existing_user(monkeypatch, url_mock_keycloak, user_to_delete):
    monkeypatch.setattr(keycloak_user.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_user.AnsibleModule, 'fail_json', fail_json)
    arguments = {
            'auth_keycloak_url': 'http://keycloak.url/auth',
            'auth_username': 'test_admin',
            'auth_password': 'admin_password',
            'auth_realm': 'master',
            'state': 'absent'
        }
    arguments.update(user_to_delete)
    set_module_args(arguments)
    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_user.main()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == ('User %s has been deleted.' % list(user_to_delete.values())[0])


@pytest.fixture(params=[
    {'keycloak_username': 'user1'},
    {'id': '883eeb5e-51d0-4aa9-8cb7-667f53e62e90'}], ids=['with name', 'with_id'])
def build_dict_request(request):
    new_response_dictionary = RESPONSE_ADMIN_ONLY.copy()
    if 'keycloak_username' in request.param.keys():
        new_response_dictionary.update({
            'http://keycloak.url/auth/admin/realms/master/users/883eeb5e-51d0-4aa9-8cb7-667f53e62e90': {
                'PUT': None,
                'GET':create_wrapper(UPDATED_USER)
            }})
    else:
        new_response_dictionary .update({
            'http://keycloak.url/auth/admin/realms/master/users/883eeb5e-51d0-4aa9-8cb7-667f53e62e90': {
                'PUT': None,
                'GET': [create_wrapper(GET_USER_BY_ID),
                        create_wrapper(UPDATED_USER)
                        ]
            }})
    return request.param, new_response_dictionary


@pytest.fixture()
def dynamic_url_mock_keycloak(mocker, build_dict_request):
    parameters, response_dictionary = build_dict_request
    return parameters, mocker.patch(
        'ansible.module_utils.keycloak.open_url',
        side_effect=build_mocked_request(count(), response_dictionary),
        autospec=True
    )


def test_state_present_should_update_existing_user(monkeypatch, dynamic_url_mock_keycloak, request):
    user_to_update, _ = dynamic_url_mock_keycloak
    monkeypatch.setattr(keycloak_user.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_user.AnsibleModule, 'fail_json', fail_json)
    arguments = {
            'auth_keycloak_url': 'http://keycloak.url/auth',
            'auth_username': 'test_admin',
            'auth_password': 'admin_password',
            'auth_realm': 'master',
            'state': 'present',
            'email': 'user1@domain.net'
        }
    arguments.update(user_to_update)
    set_module_args(arguments)
    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_user.main()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == ('User %s has been updated.' % list(user_to_update.values())[0])
    assert ansible_exit_json['end_state'] == json.loads(UPDATED_USER)

