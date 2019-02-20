from __future__ import (absolute_import, division, print_function)

import json
from itertools import count

import pytest

from ansible.module_utils.six import StringIO
from ansible.modules.identity.keycloak import keycloak_roles
from units.modules.utils import (
    AnsibleExitJson, AnsibleFailJson, fail_json, exit_json, set_module_args)
from ansible.module_utils.six.moves.urllib.error import HTTPError


def create_wrapper(text_as_string):
    """Allow to mock many times a call to one address.
    Without this function, the StringIO is empty for the second call.
    """
    def _create_wrapper():
        return StringIO(text_as_string)
    return _create_wrapper


CONNECTION_DICT = {
    'http://keycloak.url/auth/realms/master/protocol/openid-connect/token': create_wrapper('{"access_token": "a long token"}'),}

DEFAULT_ROLES = [
    {'id': 'c02533c5-d943-4274-9953-8b6a930ee74e', 'name': 'admin',
     'description': '${role_admin}', 'composite': True,
     'clientRole': False, 'containerId': 'master'},
    {'id': '9d78de2a-f790-432d-b24b-9d2102fd2957',
     'name': 'offline_access',
     'description': '${role_offline-access}', 'composite': False,
     'clientRole': False, 'containerId': 'master'}]


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
        try:
            call_number = get_id_call_count.__next__()
        except AttributeError:
            # manage python 2 versions.
            call_number = get_id_call_count.next()
        return get_response(
            object_with_future_response[call_number], method, get_id_call_count)
    return object_with_future_response


@pytest.fixture
def mock_absent_role_url(mocker):
    absent_role_url = CONNECTION_DICT.copy()
    absent_role_url.update({
        'http://keycloak.url/auth/admin/realms/master/roles': create_wrapper(json.dumps(DEFAULT_ROLES)),
        'http://keycloak.url/auth/admin/realms/master/roles/00000000-0000-0000-0000-000000000000':
            lambda: (_ for _ in ()).throw(HTTPError(url='roles/00000000-0000-0000-0000-000000000000', code=404, msg='does not exists', hdrs='', fp=StringIO('')))
    })
    return mocker.patch(
        'ansible.module_utils.keycloak.open_url',
        side_effect=build_mocked_request(count(), absent_role_url),
        autospec=True
    )


@pytest.mark.parametrize('role_identifier,error_message', [
    ({'name': 'absent'}, 'Role absent does not exist in realm master'),
    ({'id': '00000000-0000-0000-0000-000000000000'},
     'Role 00000000-0000-0000-0000-000000000000 does not exist in realm master'),
    ({'client_id': 'absent-client', 'name': 'absent'},
     'Client absent-client does not exists, cannot found role absent in it'),
    ({'client_id': 'client-with-role', 'name': 'absent'},
     'Role absent does not exist in client-with-role client'),
    ({'client_name': 'Client with role', 'id': '00000000-0000-0000-0000-000000000000'},
     'Role 00000000-0000-0000-0000-000000000000 does not exist in client-with-role client'),
], ids=['with name', 'with id', 'role in client, client does not exist',
        'role name in client with id', 'role id in client with id'])
def test_state_absent_should_not_create_absent_role(
        monkeypatch, role_identifier, error_message, mock_absent_role_url):
    """This function mainly test the get_initial_role and do_nothing_and_exit functions
    """
    monkeypatch.setattr(keycloak_roles.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_roles.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'absent'
    }
    arguments.update(role_identifier)
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_roles.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == (error_message + ', doing nothing.')


@pytest.fixture
def mock_delete_role_url(mocker):
    absent_role_url = CONNECTION_DICT.copy()
    existing_role = DEFAULT_ROLES.copy()
    existing_role.append({
        'id': 'cccccccc-d943-4274-9953-8b6a930ee74e', 'name': 'to delete',
        'description': 'to be deleted during test', 'composite': False,
        'clientRole': False, 'containerId': 'master'},)
    absent_role_url.update({
        'http://keycloak.url/auth/admin/realms/master/roles': create_wrapper(json.dumps(existing_role)),
        'http://keycloak.url/auth/admin/realms/master/roles-by-id/cccccccc-d943-4274-9953-8b6a930ee74e': None
    })
    return mocker.patch(
        'ansible.module_utils.keycloak.open_url',
        side_effect=build_mocked_request(count(), absent_role_url),
        autospec=True
    )


def test_state_absent_with_existing_role_should_delete_the_role(
        monkeypatch, mock_delete_role_url):
    monkeypatch.setattr(keycloak_roles.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_roles.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'absent',
        'name': 'to delete'
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_roles.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == 'Role to delete has been deleted.'
