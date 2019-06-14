# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)

import pytest
from itertools import count
import json

from ansible.module_utils.six import StringIO
from units.modules.utils import (
    AnsibleExitJson, AnsibleFailJson, fail_json, exit_json, set_module_args)
from ansible.modules.identity.keycloak import keycloak_group_role_mapping
from ansible.module_utils.six.moves.urllib.error import HTTPError


def raise_404(url):
    def _raise_404():
        raise HTTPError(url=url, code=404, msg='does not exist', hdrs='', fp=StringIO(''))
    return _raise_404


def create_wrapper(text_as_string):
    """Allow to mock many times a call to one address.
    Without this function, the StringIO is empty for the second call.
    """
    def _create_wrapper():
        return StringIO(text_as_string)
    return _create_wrapper


def build_mocked_request(get_id_user_count, response_dict):
    def _mocked_requests(*args, **kwargs):
        try:
            url = args[0]
        except IndexError:
            url = kwargs['url']
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


CONNECTION_DICT = {
    'http://keycloak.url/auth/realms/master/protocol/openid-connect/token': create_wrapper(
        '{"access_token": "a long token"}'),
    'http://keycloak.url/auth/admin/realms/master/groups': create_wrapper(
        json.dumps([{'id': '111-111', 'name': 'one_group'}])),
    'http://keycloak.url/auth/admin/realms/master/groups/111-111': create_wrapper(
        json.dumps({'id': '111-111', 'name': 'one_group'})),
    'http://keycloak.url/auth/admin/realms/master/clients?clientId=one_client': create_wrapper(
        json.dumps([{'id': '333-333', 'clientId': 'one_client'}])),
}


@pytest.fixture
def mock_doing_nothing_urls(mocker):
    doing_nothing_urls = CONNECTION_DICT.copy()
    doing_nothing_urls.update({
        'http://keycloak.url/auth/admin/realms/master/groups/111-111/role-mappings/realm/composite': create_wrapper(
            json.dumps({})),
        'http://keycloak.url/auth/admin/realms/master/roles/one_role': create_wrapper(
            json.dumps({'id': '222-222', 'name': 'one_role'})),
        'http://keycloak.url/auth/admin/realms/master/clients/333-333/roles/role_in_client': create_wrapper(
            json.dumps({'id': '444-444', 'name': 'role_in_client'})),
        'http://keycloak.url/auth/admin/realms/master/groups/111-111/role-mappings/clients/333-333/composite': create_wrapper(
            json.dumps([])),
    })
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), doing_nothing_urls),
        autospec=True
    )


@pytest.mark.parametrize('extra_arguments, waited_message', [
    ({'role_name': 'one_role'},
     'Links between one_group and one_role does not exist, doing nothing.'),
    ({'role_name': 'role_in_client', 'client_id': 'one_client'},
     'Links between one_group and role_in_client in one_client does_not_exist, doing nothing.')
], ids=['role in realm master', 'role in client'])
def test_state_absent_without_link_should_not_do_something(
        monkeypatch, extra_arguments, waited_message, mock_doing_nothing_urls):
    monkeypatch.setattr(keycloak_group_role_mapping.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_group_role_mapping.AnsibleModule, 'fail_json', fail_json)
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
        keycloak_group_role_mapping.main()
    ansible_exit_json = exec_trace.value.args[0]
    assert not ansible_exit_json['changed']
    assert ansible_exit_json['msg'] == waited_message
    assert ansible_exit_json['roles_in_group'] == {}


@pytest.fixture
def mock_creation_url(mocker):
    creation_urls = CONNECTION_DICT.copy()
    creation_urls.update({
        'http://keycloak.url/auth/admin/realms/master/groups': create_wrapper(
            json.dumps([{'id': '555-555', 'name': 'to_link'}])),
        'http://keycloak.url/auth/admin/realms/master/groups/555-555': create_wrapper(
            json.dumps({'id': '555-555', 'name': 'to_link'})),
        'http://keycloak.url/auth/admin/realms/master/groups/555-555/role-mappings/realm/composite': [
            create_wrapper(json.dumps({})),
            create_wrapper(json.dumps([{'id': '222-222', 'name': 'one_role'}]))
        ],
        'http://keycloak.url/auth/admin/realms/master/roles/one_role': create_wrapper(
            json.dumps({'id': '222-222', 'name': 'one_role'})),
        'http://keycloak.url/auth/admin/realms/master/groups/111-111/role-mappings/realm/': None,
        'http://keycloak.url/auth/admin/realms/master/groups/555-555/role-mappings/clients/333-333/composite': [
            create_wrapper(json.dumps(({}))),
            create_wrapper(json.dumps([{'id': 'b4af56e4-869a-44de-97b5-10c7d1bb9664', 'name': 'role_to_link_in_client'}]))
        ],
        'http://keycloak.url/auth/admin/realms/master/clients/333-333/roles/role_to_link_in_client': create_wrapper(
            json.dumps({'id': 'b4af56e4-869a-44de-97b5-10c7d1bb9664', 'name': 'role_to_link_in_client'})
        ),
        'http://keycloak.url/auth/admin/realms/master/roles-by-id/222-222': create_wrapper(
            json.dumps({'id': '222-222', 'name': 'one_role'})),
    })
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), creation_urls),
        autospec=True
    )


@pytest.mark.parametrize('extra_arguments, waited_message', [
    ({'group_name': 'to_link', 'role_name': 'one_role'}, 'Link between to_link and one_role created.'),
    ({'group_name': 'to_link', 'role_name': 'role_to_link_in_client', 'client_id': 'one_client'},
     'Link between to_link and role_to_link_in_client in one_client created.'),
    ({'group_id': '555-555', 'role_id': '222-222'},
     'Link between 555-555 and 222-222 created.')
], ids=['with name in realm', 'with name one client', 'with uuid for groups and roles'])
def test_state_present_without_link_should_create_link(
        monkeypatch, extra_arguments, waited_message, mock_creation_url):
    monkeypatch.setattr(keycloak_group_role_mapping.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_group_role_mapping.AnsibleModule, 'fail_json', fail_json)
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
        keycloak_group_role_mapping.main()
    ansible_exit_json = exec_trace.value.args[0]
    assert ansible_exit_json['msg'] == waited_message
    assert ansible_exit_json['changed']
    if 'role_name' in extra_arguments:
        assert ansible_exit_json['roles_in_group']['name'] == extra_arguments['role_name']
    else:
        assert ansible_exit_json['roles_in_group']['id'] == extra_arguments['role_id']


@pytest.fixture()
def existing_nothing_to_do(mocker):
    nothing_to_do_url = CONNECTION_DICT.copy()
    nothing_to_do_url.update({
        'http://keycloak.url/auth/admin/realms/master/groups/111-111/role-mappings/realm/composite': create_wrapper(
            json.dumps([{'id': '456-456', 'name': 'already_link_role'}, ])
        ),
        'http://keycloak.url/auth/admin/realms/master/roles/already_link_role': create_wrapper(
            json.dumps({'id': '456-456', 'name': 'already_link_role'})
        ),
        'http://keycloak.url/auth/admin/realms/master/clients/333-333/roles/role_in_client': create_wrapper(
            json.dumps({'id': '789-789', 'name': 'already_link_role'})),
        'http://keycloak.url/auth/admin/realms/master/groups/111-111/role-mappings/clients/333-333/composite': create_wrapper(
            json.dumps([{'id': '789-789', 'name': 'already_link_role', }, ])
        ),
        'http://keycloak.url/auth/admin/realms/master/clients/333-333/roles/already_link_role': create_wrapper(
            json.dumps({'id': '789-789', 'name': 'already_link_role', })
        ),
    })
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), nothing_to_do_url),
        autospec=True
    )


@pytest.mark.parametrize('extra_arguments, waited_message', [
    ({'group_name': 'one_group', 'role_name': 'already_link_role'},
     'Links between one_group and already_link_role exists, doing nothing.'),
    ({'group_name': 'one_group', 'role_name': 'already_link_role', 'client_id': 'one_client'},
     'Links between one_group and already_link_role in one_client exists, doing nothing.')
], ids=['role in master', 'role in client'])
def test_state_present_with_link_should_no_do_something(
    monkeypatch, extra_arguments, waited_message, existing_nothing_to_do
):
    monkeypatch.setattr(keycloak_group_role_mapping.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_group_role_mapping.AnsibleModule, 'fail_json', fail_json)
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
        keycloak_group_role_mapping.main()
    ansible_exit_json = exec_trace.value.args[0]
    assert not ansible_exit_json['changed']
    assert ansible_exit_json['msg'] == waited_message
    assert ansible_exit_json['roles_in_group']['name'] == extra_arguments['role_name']


@pytest.fixture()
def to_delete(mocker):
    delete_urls = CONNECTION_DICT.copy()
    delete_urls.update({
        'http://keycloak.url/auth/admin/realms/master/groups/111-111/role-mappings/realm/composite': create_wrapper(
            json.dumps([{'id': '987-987', 'name': 'to_unlink'}, ])
        ),
        'http://keycloak.url/auth/admin/realms/master/roles/to_unlink': create_wrapper(
            json.dumps({'id': '987-987', 'name': 'to_unlink', })
        ),
        'http://keycloak.url/auth/admin/realms/master/groups/111-111/role-mappings/realm/': create_wrapper(
            json.dumps({})
        ),
        'http://keycloak.url/auth/admin/realms/master/groups/111-111/role-mappings/clients/333-333/composite': create_wrapper(
            json.dumps([{'id': '765', '765': 'to_unlink'}, ])
        ),
        'http://keycloak.url/auth/admin/realms/master/clients/333-333/roles/to_unlink': create_wrapper(
            json.dumps({'id': '765', '765': 'to_unlink'})
        )
    })
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), delete_urls),
        autospec=True
    )


@pytest.mark.parametrize('extra_arguments, waited_message', [
    ({'group_name': 'one_group', 'role_name': 'to_unlink'},
     'Links between one_group and to_unlink deleted.'),
    ({'group_name': 'one_group', 'role_name': 'to_unlink', 'client_id': 'one_client'},
     'Links between one_group and to_unlink in one_client deleted.')
], ids=['role in master', 'role in client'])
def test_state_absent_with_existing_should_delete_the_link(
        monkeypatch, extra_arguments, waited_message, to_delete):
    monkeypatch.setattr(keycloak_group_role_mapping.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_group_role_mapping.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'absent',
    }
    arguments.update(extra_arguments)
    set_module_args(arguments)
    with pytest.raises(AnsibleExitJson) as exec_trace:
        keycloak_group_role_mapping.main()
    ansible_exit_json = exec_trace.value.args[0]
    assert ansible_exit_json['changed']
    assert ansible_exit_json['msg'] == waited_message
    assert not ansible_exit_json['roles_in_group']


@pytest.fixture
def wrong_parameter_url(mocker):
    wrong_parameter_urls = CONNECTION_DICT.copy()
    wrong_parameter_urls.update({
        'http://keycloak.url/auth/admin/realms/master/groups/000-000': raise_404('groups/000-000'),
        'http://keycloak.url/auth/admin/realms/master/groups/111-111/role-mappings/realm/composite': create_wrapper(
            json.dumps([])
        ),
        'http://keycloak.url/auth/admin/realms/master/roles/doesnotexist': raise_404('roles/doesnotexist'),
        'http://keycloak.url/auth/admin/realms/master/roles-by-id/000-000': raise_404('roles-by-id/000-000'),
        'http://keycloak.url/auth/admin/realms/master/clients?clientId=doesnotexist': create_wrapper(
            json.dumps([])
        ),
        'http://keycloak.url/auth/admin/realms/master/groups/111-111/role-mappings/clients/333-333/composite': create_wrapper(
            json.dumps([])
        ),
        'http://keycloak.url/auth/admin/realms/master/clients/333-333/roles/doesnotexist': raise_404('333-333/roles/doesnotexist'),
    })
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), wrong_parameter_urls),
        autospec=True
    )


@pytest.mark.parametrize('extra_arguments, waited_message', [
    ({'group_name': 'doesnotexist', 'role_name': 'one_role'},
     'group doesnotexist not found.'),
    ({'group_id': '000-000', 'role_name': 'one_role'},
     'group 000-000 not found.'),
    ({'group_name': 'one_group', 'role_name': 'doesnotexist'},
     'role doesnotexist not found.'),
    ({'group_name': 'one_group', 'role_id': '000-000'},
     'role 000-000 not found.'),
    ({'group_name': 'one_group', 'role_name': 'one_role', 'client_id': 'doesnotexist'},
     'client doesnotexist not found.'),
    ({'group_name': 'one_group', 'role_name': 'doesnotexist', 'client_id': 'one_client'},
     'role doesnotexist not found in one_client.'),
], ids=['group name', 'group id', 'role name', 'role id', 'client name',
        'role name in client'])
def test_with_wrong_parameters(monkeypatch, extra_arguments, waited_message, wrong_parameter_url):
    monkeypatch.setattr(keycloak_group_role_mapping.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_group_role_mapping.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'absent',
    }
    arguments.update(extra_arguments)
    set_module_args(arguments)
    with pytest.raises(AnsibleFailJson) as exec_trace:
        keycloak_group_role_mapping.main()
    ansible_exit_json = exec_trace.value.args[0]
    assert ansible_exit_json['msg'] == waited_message
