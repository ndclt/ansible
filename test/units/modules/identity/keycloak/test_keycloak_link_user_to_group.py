# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

from copy import deepcopy

import pytest
from itertools import count
import json

from ansible.module_utils.six import StringIO
from units.modules.utils import (
    AnsibleExitJson,
    AnsibleFailJson,
    fail_json,
    exit_json,
    set_module_args,
)
from ansible.modules.identity.keycloak import keycloak_link_user_to_group
from ansible.module_utils.six.moves.urllib.error import HTTPError


def raise_404(url):
    def _raise_404():
        raise HTTPError(
            url=url, code=404, msg='does not exist', hdrs='', fp=StringIO('')
        )

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
            object_with_future_response[method], method, get_id_call_count
        )
    if isinstance(object_with_future_response, list):
        try:
            call_number = get_id_call_count.__next__()
        except AttributeError:
            # manage python 2 versions.
            call_number = get_id_call_count.next()
        return get_response(
            object_with_future_response[call_number], method, get_id_call_count
        )
    return object_with_future_response


def get_given_user_and_group(arguments):
    try:
        given_group = arguments['group_name']
    except KeyError:
        given_group = arguments['group_id']
    try:
        given_user = arguments['keycloak_username']
    except KeyError:
        given_user = arguments['user_id']
    return given_group, given_user


CONNECTION_DICT = {
    'http://keycloak.url/auth/realms/master/protocol/openid-connect/token': create_wrapper(
        '{"access_token": "a long token"}'
    )
}


@pytest.fixture
def mock_state_absent_no_link_to_do(mocker):
    response_dict = deepcopy(CONNECTION_DICT)
    response_dict.update(
        {
            'http://keycloak.url/auth/admin/realms/master/groups': create_wrapper(
                json.dumps(
                    [
                        {'id': '457-123', 'name': 'group1'},
                        {'id': '123-321', 'name': 'not_asked_group'},
                    ]
                )
            ),
            'http://keycloak.url/auth/admin/realms/master/groups/457-123': create_wrapper(
                (json.dumps({'id': '457-123', 'name': 'group1'}))
            ),
            'http://keycloak.url/auth/admin/realms/master/users': create_wrapper(
                json.dumps(
                    [
                        {'id': '345-543', 'username': 'user1'},
                        {'id': '890-098', 'username': 'not_asked_user'},
                    ]
                )
            ),
            'http://keycloak.url/auth/admin/realms/master/users/345-543': create_wrapper(
                json.dumps({'id': '345-543', 'username': 'user1'})
            ),
            'http://keycloak.url/auth/admin/realms/master/users/345-543/groups': create_wrapper(
                json.dumps([])
            ),
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), response_dict),
        autospec=True,
    )


@pytest.mark.parametrize(
    'extra_arguments',
    [
        {'group_name': 'group1', 'keycloak_username': 'user1'},
        {'group_id': '457-123', 'user_id': '345-543'},
    ],
    ids=['names', 'ids'],
)
def test_state_absent_without_link_should_do_nothing(
    monkeypatch, mock_state_absent_no_link_to_do, extra_arguments
):
    monkeypatch.setattr(
        keycloak_link_user_to_group.AnsibleModule, 'exit_json', exit_json
    )
    monkeypatch.setattr(
        keycloak_link_user_to_group.AnsibleModule, 'fail_json', fail_json
    )
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
        keycloak_link_user_to_group.main()
    ansible_exit_json = exec_trace.value.args[0]
    assert not ansible_exit_json['changed']
    given_group, given_user = get_given_user_and_group(arguments)
    assert ansible_exit_json['msg'] == (
        'Link between user {given_user} and group {given_group} does not exist, nothing to do.'.format(
            given_user=given_user, given_group=given_group
        )
    )
    assert ansible_exit_json['link_user_to_group'] == {}


@pytest.fixture
def mock_state_present_link_exists(mocker):
    response_dict = deepcopy(CONNECTION_DICT)
    response_dict.update(
        {
            'http://keycloak.url/auth/admin/realms/master/groups': create_wrapper(
                json.dumps(
                    [
                        {'id': '457-123', 'name': 'group1'},
                        {'id': '123-321', 'name': 'not_asked_group'},
                    ]
                )
            ),
            'http://keycloak.url/auth/admin/realms/master/groups/457-123': create_wrapper(
                (json.dumps({'id': '457-123', 'name': 'group1'}))
            ),
            'http://keycloak.url/auth/admin/realms/master/users': create_wrapper(
                json.dumps(
                    [
                        {'id': '345-543', 'username': 'user1'},
                        {'id': '890-098', 'username': 'not_asked_user'},
                    ]
                )
            ),
            'http://keycloak.url/auth/admin/realms/master/users/345-543/groups': create_wrapper(
                json.dumps([{'id': '457-123', 'name': 'group1'}])
            ),
            'http://keycloak.url/auth/admin/realms/master/users/345-543': create_wrapper(
                json.dumps({'id': '345-543', 'username': 'user1'})
            ),
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), response_dict),
        autospec=True,
    )


@pytest.mark.parametrize(
    'extra_arguments',
    [
        {'group_name': 'group1', 'keycloak_username': 'user1'},
        {'group_id': '457-123', 'user_id': '345-543'},
    ],
    ids=['names', 'ids'],
)
def test_state_present_with_link_should_do_nothing(
    monkeypatch, mock_state_present_link_exists, extra_arguments
):
    monkeypatch.setattr(
        keycloak_link_user_to_group.AnsibleModule, 'exit_json', exit_json
    )
    monkeypatch.setattr(
        keycloak_link_user_to_group.AnsibleModule, 'fail_json', fail_json
    )
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'present',
    }
    arguments.update(extra_arguments)
    given_group, given_user = get_given_user_and_group(arguments)
    set_module_args(arguments)
    with pytest.raises(AnsibleExitJson) as exec_trace:
        keycloak_link_user_to_group.main()
    ansible_exit_json = exec_trace.value.args[0]
    assert not ansible_exit_json['changed']
    assert ansible_exit_json['msg'] == (
        'Link between user {given_user} and group {given_group} exists, nothing to do.'.format(
            given_group=given_group, given_user=given_user
        )
    )
    assert ansible_exit_json['link_user_to_group'] == extra_arguments


@pytest.fixture
def mock_create_link(mocker):
    response_dict = deepcopy(CONNECTION_DICT)
    response_dict.update(
        {
            'http://keycloak.url/auth/admin/realms/master/groups': create_wrapper(
                json.dumps(
                    [
                        {'id': '457-123', 'name': 'group1'},
                        {'id': '123-321', 'name': 'not_asked_group'},
                    ]
                )
            ),
            'http://keycloak.url/auth/admin/realms/master/groups/457-123': create_wrapper(
                (json.dumps({'id': '457-123', 'name': 'group1'}))
            ),
            'http://keycloak.url/auth/admin/realms/master/users': create_wrapper(
                json.dumps(
                    [
                        {'id': '345-543', 'username': 'user1'},
                        {'id': '890-098', 'username': 'not_asked_user'},
                    ]
                )
            ),
            'http://keycloak.url/auth/admin/realms/master/users/345-543': create_wrapper(
                json.dumps({'id': '345-543', 'username': 'user1'})
            ),
            'http://keycloak.url/auth/admin/realms/master/users/345-543/groups': create_wrapper(
                json.dumps([])
            ),
            'http://keycloak.url/auth/admin/realms/master/users/345-543/groups/345-543': None,
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), response_dict),
        autospec=True,
    )


@pytest.mark.parametrize(
    'extra_arguments',
    [
        {'group_name': 'group1', 'keycloak_username': 'user1'},
        {'group_id': '457-123', 'user_id': '345-543'},
    ],
    ids=['names', 'ids'],
)
def test_state_present_should_create_non_existing_link(
    monkeypatch, mock_create_link, extra_arguments
):
    monkeypatch.setattr(
        keycloak_link_user_to_group.AnsibleModule, 'exit_json', exit_json
    )
    monkeypatch.setattr(
        keycloak_link_user_to_group.AnsibleModule, 'fail_json', fail_json
    )
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
    given_group, given_user = get_given_user_and_group(arguments)
    with pytest.raises(AnsibleExitJson) as exec_trace:
        keycloak_link_user_to_group.main()
    ansible_exit_json = exec_trace.value.args[0]
    assert ansible_exit_json['changed']
    assert ansible_exit_json['msg'] == (
        'Link between user {given_user} and group {given_group} created.'.format(
            given_user=given_user, given_group=given_group
        )
    )
    assert ansible_exit_json['link_user_to_group'] == extra_arguments


@pytest.fixture
def mock_delete_link(mocker):
    response_dict = deepcopy(CONNECTION_DICT)
    response_dict.update(
        {
            'http://keycloak.url/auth/admin/realms/master/groups': create_wrapper(
                json.dumps(
                    [
                        {'id': '457-123', 'name': 'group1'},
                        {'id': '123-321', 'name': 'not_asked_group'},
                    ]
                )
            ),
            'http://keycloak.url/auth/admin/realms/master/groups/457-123': create_wrapper(
                (json.dumps({'id': '457-123', 'name': 'group1'}))
            ),
            'http://keycloak.url/auth/admin/realms/master/users': create_wrapper(
                json.dumps(
                    [
                        {'id': '345-543', 'username': 'user1'},
                        {'id': '890-098', 'username': 'not_asked_user'},
                    ]
                )
            ),
            'http://keycloak.url/auth/admin/realms/master/users/345-543': create_wrapper(
                json.dumps({'id': '345-543', 'username': 'user1'})
            ),
            'http://keycloak.url/auth/admin/realms/master/users/345-543/groups': create_wrapper(
                json.dumps([{'id': '457-123', 'name': 'group1'}])
            ),
            'http://keycloak.url/auth/admin/realms/master/users/345-543/groups/345-543': None,
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), response_dict),
        autospec=True,
    )


@pytest.mark.parametrize(
    'extra_arguments',
    [
        {'group_name': 'group1', 'keycloak_username': 'user1'},
        {'group_id': '457-123', 'user_id': '345-543'},
    ],
    ids=['names', 'ids'],
)
def test_state_absent_should_delete_existing_link(
    monkeypatch, mock_delete_link, extra_arguments
):
    monkeypatch.setattr(
        keycloak_link_user_to_group.AnsibleModule, 'exit_json', exit_json
    )
    monkeypatch.setattr(
        keycloak_link_user_to_group.AnsibleModule, 'fail_json', fail_json
    )
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
    given_group, given_user = get_given_user_and_group(arguments)
    with pytest.raises(AnsibleExitJson) as exec_trace:
        keycloak_link_user_to_group.main()
    ansible_exit_json = exec_trace.value.args[0]
    assert ansible_exit_json['changed']
    assert ansible_exit_json['msg'] == (
        'Link between user {given_user} and group {given_group} deleted.'.format(
            given_user=given_user, given_group=given_group
        )
    )
    assert ansible_exit_json['link_user_to_group'] == {}


@pytest.fixture
def mock_does_not_exist(mocker):
    response_dict = deepcopy(CONNECTION_DICT)
    response_dict.update(
        {
            'http://keycloak.url/auth/admin/realms/master/groups': create_wrapper(
                json.dumps(
                    [
                        {'id': '457-123', 'name': 'group1'},
                        {'id': '123-321', 'name': 'not_asked_group'},
                    ]
                )
            ),
            'http://keycloak.url/auth/admin/realms/master/groups/457-123': create_wrapper(
                (json.dumps({'id': '457-123', 'name': 'group1'}))
            ),
            'http://keycloak.url/auth/admin/realms/master/users': create_wrapper(
                json.dumps(
                    [
                        {'id': '345-543', 'username': 'user1'},
                        {'id': '890-098', 'username': 'not_asked_user'},
                    ]
                )
            ),
            'http://keycloak.url/auth/admin/realms/master/users/345-543': create_wrapper(
                json.dumps({'id': '345-543', 'username': 'user1'})
            ),
            'http://keycloak.url/auth/admin/realms/master/users/111-111': raise_404(
                'users/111-111'
            ),
            'http://keycloak.url/auth/admin/realms/master/groups/222-222': raise_404(
                'groups/222-222'
            ),
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), response_dict),
        autospec=True,
    )


@pytest.mark.parametrize(
    'extra_arguments',
    [
        {'group_name': 'does_not_exist', 'keycloak_username': 'user1'},
        {'group_id': '222-222', 'user_id': '345-543'},
        {'group_name': 'group1', 'keycloak_username': 'does_not_exist'},
        {'group_id': '457-123', 'user_id': '111-111'},
    ],
    ids=['group name', 'group id', 'user name', 'user id'],
)
def test_group_or_user_does_not_exist_should_fail(
    monkeypatch, mock_does_not_exist, extra_arguments, request
):
    test_id = request.node.nodeid.split('[')[1].split(']')[0]
    monkeypatch.setattr(
        keycloak_link_user_to_group.AnsibleModule, 'exit_json', exit_json
    )
    monkeypatch.setattr(
        keycloak_link_user_to_group.AnsibleModule, 'fail_json', fail_json
    )
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
    given_group, given_user = get_given_user_and_group(arguments)
    with pytest.raises(AnsibleFailJson) as exec_trace:
        keycloak_link_user_to_group.main()
    ansible_exit_json = exec_trace.value.args[0]
    if 'group' in test_id:
        assert ansible_exit_json['msg'] == 'Group {} does not exist'.format(given_group)
    else:
        assert ansible_exit_json['msg'] == 'User {} does not exist'.format(given_user)
