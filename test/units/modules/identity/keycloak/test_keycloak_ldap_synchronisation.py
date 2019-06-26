# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
from copy import deepcopy
from itertools import count

import pytest
from ansible.module_utils._text import to_text
from ansible.module_utils.six import StringIO
from ansible.modules.identity.keycloak import keycloak_ldap_synchronization
from units.modules.utils import (
    AnsibleExitJson,
    AnsibleFailJson,
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


CONNECTION_DICT = {
    'http://keycloak.url/auth/realms/master/protocol/openid-connect/token': create_wrapper(
        '{"access_token": "a long token"}'
    )
}


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


@pytest.fixture
def mock_absent_url(mocker):
    absent_federation = deepcopy(CONNECTION_DICT)
    absent_federation.update(
        {
            'http://keycloak.url/auth/admin/realms/master/components?parent=master&type=org.keycloak.storage.UserStorageProvider&name=does-not-exist': create_wrapper(
                json.dumps([])
            )
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), absent_federation),
        autospec=True,
    )


def test_federation_does_not_exist_fail(monkeypatch, mock_absent_url):
    monkeypatch.setattr(keycloak_ldap_synchronization.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_synchronization.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'federation_id': 'does-not-exist',
        'synchronize_changed_users': True,
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleFailJson) as exec_error:
        keycloak_ldap_synchronization.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == to_text(
        'Cannot synchronize does-not-exist federation because it does not exist.'
    )


@pytest.fixture
def mock_synchronisation_url(mocker):
    absent_federation = deepcopy(CONNECTION_DICT)
    absent_federation.update(
        {
            'http://keycloak.url/auth/admin/realms/master/components?parent=master&type=org.keycloak.storage.UserStorageProvider&name=company-ldap': create_wrapper(
                json.dumps(
                    [
                        {
                            'id': '123-123',
                            'name': 'company-ldap',
                            'parentId': 'master',
                            'config': {'pagination': [True], 'bindDn': ['cn:admin']},
                        }
                    ]
                )
            ),
            'http://keycloak.url/auth/admin/realms/master/user-storage/123-123/sync?action=triggerChangedUsersSync': create_wrapper(
                json.dumps(
                    {
                        'ignored': False,
                        'added': 0,
                        'updated': 2,
                        'removed': 1,
                        'failed': 0,
                        'status': '0 imported users, 2 updated users',
                    }
                )
            ),
            'http://keycloak.url/auth/admin/realms/master/user-storage/123-123/sync?action=triggerFullSync': create_wrapper(
                json.dumps(
                    {
                        'ignored': False,
                        'added': 2,
                        'updated': 2,
                        'removed': 1,
                        'failed': 0,
                        'status': '2 imported users, 2 updated users, 1 removed',
                    }
                )
            ),
            'http://keycloak.url/auth/admin/realms/master/user-storage/123-123/remove-imported-users': create_wrapper(
                ''
            ),
            'http://keycloak.url/auth/admin/realms/master/user-storage/123-123/unlink-users': create_wrapper(
                ''
            ),
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), absent_federation),
        autospec=True,
    )


@pytest.mark.parametrize(
    'extra_arguments, waited_message, url_keyword',
    [
        (
            {'synchronize_all_users': True},
            '2 imported users, 2 updated users, 1 removed.',
            'triggerFullSync',
        ),
        (
            {'synchronize_changed_users': True},
            '0 imported users, 2 updated users.',
            'triggerChangedUsersSync',
        ),
        (
            {'remove_imported': True},
            'Remove imported users from company-ldap.',
            'remove-imported-users',
        ),
        ({'unlink_users': True}, 'Unlink users of company-ldap.', 'unlink-users'),
    ],
    ids=['Synchronize all users', 'Synchronize changed users', 'Remove users', 'Unlink users'],
)
def test_synchronize_change_user(
    monkeypatch, extra_arguments, waited_message, url_keyword, mock_synchronisation_url
):
    monkeypatch.setattr(keycloak_ldap_synchronization.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_synchronization.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'federation_id': 'company-ldap',
    }
    arguments.update(extra_arguments)
    set_module_args(arguments)
    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_ldap_synchronization.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['changed']
    assert ansible_exit_json['msg'] == to_text(waited_message)
    calls = mock_synchronisation_url.mock_calls
    urls = [one_call[1][0] for one_call in calls]
    keyword_found = False
    for one_url in urls:
        if url_keyword in one_url:
            keyword_found = True
    assert keyword_found


@pytest.fixture
def mock_fail_synchronisation_url(mocker):
    absent_federation = deepcopy(CONNECTION_DICT)
    absent_federation.update(
        {
            'http://keycloak.url/auth/admin/realms/master/components?parent=master&type=org.keycloak.storage.UserStorageProvider&name=company-ldap': create_wrapper(
                json.dumps(
                    [
                        {
                            'id': '123-123',
                            'name': 'company-ldap',
                            'parentId': 'master',
                            'config': {'pagination': [True], 'bindDn': ['cn:admin']},
                        }
                    ]
                )
            ),
            'http://keycloak.url/auth/admin/realms/master/user-storage/123-123/sync?action=triggerFullSync': create_wrapper(
                json.dumps(
                    {
                        'ignored': False,
                        'added': 0,
                        'updated': 0,
                        'removed': 0,
                        'failed': 5,
                        'status': '0 imported users, 0 updated users, 5 users failed sync! See server log for more details',
                    }
                )
            ),
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), absent_federation),
        autospec=True,
    )


def test_fail_synchronisation(monkeypatch, mock_fail_synchronisation_url):
    monkeypatch.setattr(keycloak_ldap_synchronization.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_synchronization.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'federation_id': 'company-ldap',
        'synchronize_all_users': True,
    }
    set_module_args(arguments)
    with pytest.raises(AnsibleFailJson) as exec_error:
        keycloak_ldap_synchronization.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert not ansible_exit_json['changed']
    assert ansible_exit_json['msg'] == to_text(
        '0 imported users, 0 updated users, 5 users failed sync! See server log for more details.'
    )
