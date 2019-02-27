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

MASTER_CLIENTS = [
    {
        'id': '11111111-1111-1111-1111-111111111111',
        'clientId': 'client-with-role',
        'name': 'Client with role number 1',
        'surrogateAuthRequired': False,
        'enabled': True,
        'clientAuthenticatorType': 'client-secret',
        'redirectUris': [],
        'webOrigins': [],
        'notBefore': 0,
        'bearerOnly': False,
        'consentRequired': False,
        'standardFlowEnabled': False,
        'implicitFlowEnabled': False,
        'directAccessGrantsEnabled': True,
        'serviceAccountsEnabled': False,
        'publicClient': True,
        'frontchannelLogout': False,
        'protocol': 'openid-connect',
        'attributes': {},
        'authenticationFlowBindingOverrides': {},
        'fullScopeAllowed': False,
        'nodeReRegistrationTimeout': 0,
        'defaultClientScopes': [
            'web-origins',
            'role_list',
            'profile',
            'roles',
            'email'
        ],
        'optionalClientScopes': [
            'address',
            'phone',
            'offline_access'
        ],
        'access': {
            'view': True,
            'configure': True,
            'manage': True
        }
    },
]


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


def raise_404(url):
    def _raise_404():
        raise HTTPError(url=url, code=404, msg='does not exist', hdrs='', fp=StringIO(''))
    return _raise_404


@pytest.fixture
def mock_absent_role_url(mocker):
    absent_role_url = CONNECTION_DICT.copy()
    absent_role_url.update({
        'http://keycloak.url/auth/admin/realms/master/roles/absent': raise_404('master/roles/absent'),
        'http://keycloak.url/auth/admin/realms/master/roles/00000000-0000-0000-0000-000000000000':
            raise_404('roles/00000000-0000-0000-0000-000000000000'),
        'http://keycloak.url/auth/admin/realms/master/clients?clientId=absent-client': create_wrapper(json.dumps({})),
        'http://keycloak.url/auth/admin/realms/master/clients?clientId=client-with-role': create_wrapper(json.dumps(MASTER_CLIENTS)),
        'http://keycloak.url/auth/admin/realms/master/clients/11111111-1111-1111-1111-111111111111/roles/absent':
            raise_404('clients/11111111-1111-1111-1111-111111111111/roles/absent'),
        'http://keycloak.url/auth/admin/realms/master/clients/11111111-1111-1111-1111-111111111111/roles/00000000-0000-0000-0000-000000000000':
            raise_404('clients/11111111-1111-1111-1111-111111111111/roles/absent/00000000-0000-0000-0000-000000000000')

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
     'Client absent-client does not exist in master, cannot found role absent in it'),
    ({'client_id': 'client-with-role', 'name': 'absent'},
     'Role absent does not exist in client client-with-role of realm master'),
    ({'client_id': 'client-with-role', 'id': '00000000-0000-0000-0000-000000000000'},
     'Role 00000000-0000-0000-0000-000000000000 does not exist in client client-with-role of realm master'),
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
def mock_delete_role_urls(mocker):
    delete_role_urls = CONNECTION_DICT.copy()
    to_delete_role_in_master = {
        'id': 'cccccccc-d943-4274-9953-8b6a930ee74e', 'name': 'to delete',
        'description': 'to be deleted during test', 'composite': False,
        'clientRole': False, 'containerId': 'master'}
    to_delete_role_in_client = {
        "id": "bbbbbbbb-acca-463b-bd93-2e7fd66022f6", "name": "to delete",
        "composite": False, "clientRole": True,
        "containerId": "11111111-1111-1111-1111-111111111111", "attributes": {}}
    delete_role_urls.update({
        'http://keycloak.url/auth/admin/realms/master/roles/to%20delete': create_wrapper(json.dumps(to_delete_role_in_master)),
        'http://keycloak.url/auth/admin/realms/master/clients?clientId=client-with-role': create_wrapper(json.dumps(MASTER_CLIENTS)),
        'http://keycloak.url/auth/admin/realms/master/clients/11111111-1111-1111-1111-111111111111/roles/to%20delete': create_wrapper(json.dumps(to_delete_role_in_client)),
        'http://keycloak.url/auth/admin/realms/master/roles-by-id/cccccccc-d943-4274-9953-8b6a930ee74e': None,
        'http://keycloak.url/auth/admin/realms/master/roles-by-id/bbbbbbbb-acca-463b-bd93-2e7fd66022f6': None
    })
    return mocker.patch(
        'ansible.module_utils.keycloak.open_url',
        side_effect=build_mocked_request(count(), delete_role_urls),
        autospec=True
    )


@pytest.mark.parametrize('client_id', [
    {},
    {'client_id': 'client-with-role'}
], ids=['role in realm', 'role in client'])
def test_state_absent_with_existing_role_should_delete_the_role(
        monkeypatch, client_id, mock_delete_role_urls):
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
    arguments.update(client_id)
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_roles.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == 'Role to delete has been deleted.'
