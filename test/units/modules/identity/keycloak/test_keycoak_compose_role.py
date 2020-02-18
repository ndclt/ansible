# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

import json
from itertools import count

import pytest
from ansible.module_utils.six import StringIO
from ansible.modules.identity.keycloak import keycloak_compose_role
from units.modules.utils import (
    AnsibleFailJson,
    AnsibleExitJson,
    fail_json,
    exit_json,
    set_module_args,
)


def create_wrapper(text_as_string):
    """Allow to mock many times a call to one address.
    Without this function, the StringIO is empty for the second call.
    """

    def _create_wrapper():
        return StringIO(text_as_string)

    return _create_wrapper


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
        return get_response(object_with_future_response[method], method, get_id_call_count)
    if isinstance(object_with_future_response, list):
        try:
            call_number = get_id_call_count.__next__()
        except AttributeError:
            # manage python 2 versions.
            call_number = get_id_call_count.next()
        return get_response(object_with_future_response[call_number], method, get_id_call_count)
    return object_with_future_response


CONNECTION_DICT = {
    'http://keycloak.url/auth/realms/master/protocol/openid-connect/token': create_wrapper(
        '{"access_token": "a long token"}'
    ),
}


@pytest.fixture
def mock_token(mocker):
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), CONNECTION_DICT),
        autospec=True,
    )


@pytest.mark.parametrize(
    'composite_roles, waited_message_start, waited_argument_names, argument_name_separator',
    [
        ([{}], 'one of the following is required', sorted(['name', 'id']), ', '),
        (
            [{'client_id': 'a_client', 'id': '00-00'}],
            'parameters are mutually exclusive',
            sorted(['id', 'client_id']),
            '|',
        ),
    ],
    ids=['all keys missing', 'client_id and id are not compatible'],
)
def test_check_composite_roles_mandatory_keys(
    monkeypatch,
    composite_roles,
    waited_message_start,
    waited_argument_names,
    argument_name_separator,
    mock_token,
):
    monkeypatch.setattr(keycloak_compose_role.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_compose_role.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'present',
        'name': 'role1',
    }
    arguments.update({'composites': composite_roles})
    set_module_args(arguments)

    with pytest.raises(AnsibleFailJson) as exec_trace:
        keycloak_compose_role.run_module()
    returned_dict = exec_trace.value.args[0]
    message_start, argument_part = returned_dict['msg'].split(':')
    assert message_start == waited_message_start
    argument_names = sorted(argument_part.strip().split(argument_name_separator))
    assert waited_argument_names == argument_names
    assert not returned_dict['changed']
    assert not returned_dict['compose_role']


EXISTING_ROLE_DICT = CONNECTION_DICT.copy()
EXISTING_ROLE_DICT.update(
    {
        'http://keycloak.url/auth/admin/realms/master/roles/role1_in_master': create_wrapper(
            json.dumps({'id': '001-001-001', 'name': 'role1_in_master', 'attributes': {}})
        ),
        'http://keycloak.url/auth/admin/realms/master/roles/to_link': create_wrapper(
            json.dumps({'name': 'to_link', 'id': '005-002-002', 'attributes': {}})
        ),
        'http://keycloak.url/auth/admin/realms/master/clients?clientId=one_client': create_wrapper(
            json.dumps([{'clientId': 'one_client', 'id': '000-000-000'}])
        ),
        'http://keycloak.url/auth/admin/realms/master/clients': create_wrapper(
            json.dumps(
                [
                    {'clientId': 'one_client', 'id': '000-000-000'},
                    {'clientId': 'account', 'id': '003-003-003'},
                ]
            )
        ),
        'http://keycloak.url/auth/admin/realms/master/clients/000-000-000/roles/role1_in_one_client': create_wrapper(
            json.dumps({'id': '002-002-002', 'name': 'role1_in_one_client', 'attributes': {}})
        ),
    }
)

ABSENT_COMPOSITES = EXISTING_ROLE_DICT.copy()
ABSENT_COMPOSITES.update(
    {
        'http://keycloak.url/auth/admin/realms/master/roles-by-id/001-001-001/composites/realm': create_wrapper(
            '{}'
        ),
        'http://keycloak.url/auth/admin/realms/master/roles-by-id/001-001-001/composites/clients/000-000-000': create_wrapper(
            '{}'
        ),
        'http://keycloak.url/auth/admin/realms/master/roles-by-id/001-001-001/composites/clients/003-003-003': create_wrapper(
            json.dumps([{'id': '004-004-004', 'name': 'do not touch role'}])
        ),
    }
)


@pytest.fixture
def mock_add_composite(mocker):
    urls_dict = ABSENT_COMPOSITES.copy()
    urls_dict.update(
        {
            'http://keycloak.url/auth/admin/realms/master/roles-by-id/001-001-001/composites': create_wrapper(
                json.dumps({})
            ),
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), urls_dict),
        autospec=True,
    )


def test_link_when_not_linked(monkeypatch, mock_add_composite):
    monkeypatch.setattr(keycloak_compose_role.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_compose_role.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'present',
        'name': 'role1_in_master',
        'composites': [
            {'name': 'to_link'},
            {'name': 'role1_in_one_client', 'client_id': 'one_client'},
        ],
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as exec_trace:
        keycloak_compose_role.run_module()
    returned_dict = exec_trace.value.args[0]
    assert (
        'role1_in_one_client (one_client)' in returned_dict['msg']
        and 'to_link' in returned_dict['msg']
        and 'added to composite role role1_in_master' in returned_dict['msg']
    )
    assert returned_dict['changed']
    assert returned_dict['keycloak_compose_role'] == {
        'role': 'role1_in_master',
        'composites': {
            'added': [
                {'name': 'to_link'},
                {'name': 'role1_in_one_client', 'client_id': 'one_client'},
            ]
        },
    }


EXISTING_COMPOSITES = EXISTING_ROLE_DICT.copy()
EXISTING_COMPOSITES.update(
    {
        'http://keycloak.url/auth/admin/realms/master/roles-by-id/001-001-001/composites/realm': create_wrapper(
            json.dumps([{'name': 'to_link', 'id': '005-002-002'}])
        ),
        'http://keycloak.url/auth/admin/realms/master/roles-by-id/001-001-001/composites/clients/000-000-000': create_wrapper(
            json.dumps([{'id': '002-002-002', 'name': 'role1_in_one_client'}])
        ),
        'http://keycloak.url/auth/admin/realms/master/roles-by-id/001-001-001/composites/clients/003-003-003': create_wrapper(
            json.dumps([{'id': '004-004-004', 'name': 'do not touch role'}])
        ),
    }
)


@pytest.fixture
def mock_removed_composite(mocker):
    urls_dict = EXISTING_COMPOSITES.copy()
    urls_dict.update(
        {
            'http://keycloak.url/auth/admin/realms/master/roles-by-id/001-001-001/composites': create_wrapper(
                json.dumps({})
            ),
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), urls_dict),
        autospec=True,
    )


def test_unlink_when_linked_and_absent(monkeypatch, mock_removed_composite):
    monkeypatch.setattr(keycloak_compose_role.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_compose_role.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'absent',
        'name': 'role1_in_master',
        'composites': [
            {'name': 'to_link'},
            {'name': 'role1_in_one_client', 'client_id': 'one_client'},
        ],
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as exec_trace:
        keycloak_compose_role.run_module()
    returned_dict = exec_trace.value.args[0]
    assert (
        'role1_in_one_client (one_client)' in returned_dict['msg']
        and 'to_link' in returned_dict['msg']
        and 'removed from composite role role1_in_master' in returned_dict['msg']
    )
    assert returned_dict['changed']
    assert returned_dict['keycloak_compose_role'] == {
        'role': 'role1_in_master',
        'composites': {
            'removed': [
                {'name': 'to_link'},
                {'name': 'role1_in_one_client', 'client_id': 'one_client'},
            ]
        },
    }


@pytest.fixture()
def mock_existing_composite(mocker):
    urls_dict = EXISTING_COMPOSITES.copy()
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), urls_dict),
        autospec=True,
    )


def test_when_already_link_present_should_not_update(monkeypatch, mock_existing_composite):
    monkeypatch.setattr(keycloak_compose_role.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_compose_role.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'present',
        'name': 'role1_in_master',
        'composites': [
            {'name': 'to_link'},
            {'name': 'role1_in_one_client', 'client_id': 'one_client'},
        ],
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as exec_trace:
        keycloak_compose_role.run_module()
    returned_dict = exec_trace.value.args[0]
    assert (
        'role1_in_one_client (one_client)' in returned_dict['msg']
        and 'to_link' in returned_dict['msg']
        and 'are already composite of role role1_in_master' in returned_dict['msg']
    )
    assert not returned_dict['changed']
    assert returned_dict['keycloak_compose_role'] == {'role': 'role1_in_master', 'composites': {}}


@pytest.fixture()
def mock_no_composite(mocker):
    urls_dict = ABSENT_COMPOSITES.copy()
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), urls_dict),
        autospec=True,
    )


def test_when_not_link_absent_should_not_update(monkeypatch, mock_no_composite):
    monkeypatch.setattr(keycloak_compose_role.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_compose_role.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'absent',
        'name': 'role1_in_master',
        'composites': [
            {'name': 'to_link'},
            {'name': 'role1_in_one_client', 'client_id': 'one_client'},
        ],
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as exec_trace:
        keycloak_compose_role.run_module()
    returned_dict = exec_trace.value.args[0]
    assert (
        'role1_in_one_client (one_client)' in returned_dict['msg']
        and 'to_link' in returned_dict['msg']
        and 'are not composite of role role1_in_master' in returned_dict['msg']
    )
    assert not returned_dict['changed']
    assert returned_dict['keycloak_compose_role'] == {'role': 'role1_in_master', 'composites': {}}
