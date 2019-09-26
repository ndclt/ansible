# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
from copy import deepcopy
from itertools import count

import pytest
from ansible.modules.identity.keycloak import keycloak_client_scope_crud
from ansible.module_utils.six import StringIO
from units.modules.utils import (
    AnsibleExitJson,
    AnsibleFailJson,
    fail_json,
    exit_json,
    set_module_args,
)

CLIENT_SCOPES_SAML_DICT = {
    'id': '123-123',
    'name': 'client_scope_with_saml',
    'description': 'SAML role list',
    'protocol': 'saml',
    'attributes': {
        'consent.screen.text': '${samlRoleListScopeConsentText}',
        'display.on.consent.screen': 'true',
    },
}

CLIENT_SCOPES_OPENID_DICT = {
    'id': '456-456',
    'name': 'client_scope_with_open_id',
    'description': 'OpenID Connect built-in scope: address',
    'protocol': 'openid-connect',
    'attributes': {
        'include.in.token.scope': 'true',
        'display.on.consent.screen': 'true',
        'consent.screen.text': '${addressScopeConsentText}',
    },
}


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
        print(url)
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
def mock_absent_client_scopes_url(mocker):
    all_client_scopes = deepcopy(CONNECTION_DICT)
    all_client_scopes.update(
        {
            'http://keycloak.url/auth/admin/realms/master/client-scopes': create_wrapper(
                json.dumps([CLIENT_SCOPES_OPENID_DICT, CLIENT_SCOPES_SAML_DICT])
            )
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), all_client_scopes),
        autospec=True,
    )


def test_if_absent_absent_client_scopes_should_not_be_created(
    monkeypatch, mock_absent_client_scopes_url
):
    monkeypatch.setattr(keycloak_client_scope_crud.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_client_scope_crud.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'client_scopes_name': 'does-not-exist',
        'state': 'absent',
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_client_scope_crud.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert (
        ansible_exit_json['msg'] == 'Client scopes does-not-exist does not exist, doing nothing.'
    )
    assert not ansible_exit_json['changed']
    assert not ansible_exit_json['client_scopes']


@pytest.fixture
def mock_delete_url(mocker):
    # This fixture does not return a full federation json, just an extract
    # with parts needed in the test and some value in order to have object
    # organisation.
    delete_federation = deepcopy(CONNECTION_DICT)
    delete_federation.update(
        {
            'http://keycloak.url/auth/admin/realms/master/client-scopes': create_wrapper(
                json.dumps([CLIENT_SCOPES_OPENID_DICT, CLIENT_SCOPES_SAML_DICT])
            ),
            'http://keycloak.url/auth/admin/realms/master/components/123-123': {'DELETE': None},
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), delete_federation),
        autospec=True,
    )


def test_state_absent_should_delete_existing_client_scope(monkeypatch, mock_delete_url):
    monkeypatch.setattr(keycloak_client_scope_crud.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_client_scope_crud.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'absent',
        'client_scopes_name': 'client_scope_with_saml',
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_client_scope_crud.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == 'Client scopes client_scope_with_saml deleted.'
    assert ansible_exit_json['changed']
    assert not ansible_exit_json['client_scopes']


@pytest.fixture
def mock_create_url(mocker):
    # This fixture does not return a full federation json, just an extract
    # with parts needed in the test and some value in order to have object
    # organisation.
    delete_federation = deepcopy(CONNECTION_DICT)
    delete_federation.update(
        {
            'http://keycloak.url/auth/admin/realms/master/client-scopes': {
                'GET': [
                    create_wrapper(json.dumps([])),
                    create_wrapper(
                        json.dumps(
                            [
                                {
                                    "id": "123-123",
                                    "name": "new-client-scope-saml",
                                    "description": "a client scope description",
                                    "protocol": "saml",
                                    "attributes": {
                                        "display.on.consent.screen": "true",
                                        "consent.screen.text": "Some text for consent screen",
                                    },
                                },
                                {
                                    "id": "456-456",
                                    "name": "new-client-scope-openid",
                                    "description": "a client scope description",
                                    "protocol": "openid-connect",
                                    "attributes": {
                                        "include.in.token.scope": "true",
                                        "display.on.consent.screen": "true",
                                        "gui.order": "2",
                                        "consent.screen.text": "Some text for consent screen",
                                    },
                                },
                            ]
                        )
                    ),
                ],
                'POST': create_wrapper(json.dumps([])),
            }
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), delete_federation),
        autospec=True,
    )


@pytest.mark.parametrize(
    'extra_arguments, wanted_result',
    [
        [
            {'protocol': 'saml', 'client_scopes_name': 'new-client-scope-saml'},
            {
                'id': '123-123',
                'name': 'new-client-scope-saml',
                'description': 'a client scope description',
                'protocol': 'saml',
                'attributes': {
                    'display.on.consent.screen': True,
                    'consent.screen.text': 'Some text for consent screen',
                },
            },
        ],
        [
            {
                'protocol': 'openid-connect',
                'include_in_token_scope': True,
                'gui_order': 2,
                'client_scopes_name': 'new-client-scope-openid',
            },
            {
                'id': '456-456',
                'name': 'new-client-scope-openid',
                'description': 'a client scope description',
                'protocol': 'openid-connect',
                'attributes': {
                    'include.in.token.scope': True,
                    'display.on.consent.screen': True,
                    'gui.order': 2,
                    'consent.screen.text': 'Some text for consent screen',
                },
            },
        ],
    ],
    ids=['saml', 'openid'],
)
def test_state_present_should_create_absent_client_scope(
    monkeypatch, mock_create_url, extra_arguments, wanted_result
):
    monkeypatch.setattr(keycloak_client_scope_crud.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_client_scope_crud.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'present',
        'description': 'a client scope description',
        'display_on_consent_screen': True,
        'consent_screen_text': 'Some text for consent screen',
    }
    arguments.update(extra_arguments)
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_client_scope_crud.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == 'Client scopes {} created.'.format(
        extra_arguments['client_scopes_name']
    )
    assert ansible_exit_json['changed']
    assert ansible_exit_json['client_scopes'] == wanted_result
    create_call_arguments = json.loads(mock_create_url.mock_calls[2][2]['data'])
    wanted_result.pop('id')
    assert create_call_arguments == wanted_result


@pytest.mark.parametrize(
    'extra_arguments',
    [{'include_in_token_scope': True}, {'include_in_token_scope': False}],
    ids=['value true', 'value false'],
)
def test_creation_of_saml_with_openid_arguments_should_raise_an_error(
    monkeypatch, mock_create_url, extra_arguments
):
    monkeypatch.setattr(keycloak_client_scope_crud.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_client_scope_crud.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'present',
        'client_scopes_name': 'new-client-scope-saml',
        'description': 'a client scope description',
        'display_on_consent_screen': True,
        'consent_screen_text': 'Some text for consent screen',
        'protocol': 'saml',
    }
    arguments.update(extra_arguments)
    set_module_args(arguments)

    with pytest.raises(AnsibleFailJson) as exec_error:
        keycloak_client_scope_crud.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == (
        'include_in_token_scope should not be used whith a saml client scope'
    )
    assert not ansible_exit_json['changed']
    assert ansible_exit_json['client_scopes'] == {}


@pytest.fixture
def mock_update_url(mocker):
    updated_scope = deepcopy(CONNECTION_DICT)
    updated_scope.update(
        {
            'http://keycloak.url/auth/admin/realms/master/client-scopes': create_wrapper(
                json.dumps([CLIENT_SCOPES_OPENID_DICT])
            ),
            'http://keycloak.url/auth/admin/realms/master/client-scopes/123-123': {
                'GET': [
                    create_wrapper(
                        json.dumps(
                            {
                                "id": "123-123",
                                "name": "new-client-scope-openid",
                                "description": "a client scope description",
                                "protocol": "openid-connect",
                                "attributes": {
                                    "include.in.token.scope": "true",
                                    "display.on.consent.screen": "true",
                                    "gui.order": "2",
                                    "consent.screen.text": "Some text for consent screen",
                                },
                            }
                        )
                    ),
                    create_wrapper(
                        json.dumps(
                            {
                                "id": "123-123",
                                "name": "new-client-scope-saml",
                                "description": "another description",
                                "protocol": "saml",
                                "attributes": {
                                    "display.on.consent.screen": "false",
                                    "consent.screen.text": "Some text for consent screen",
                                },
                            }
                        )
                    ),
                ],
                'PUT': create_wrapper(json.dumps([])),
            },
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), updated_scope),
        autospec=True,
    )


def test_state_present_should_update_existing_mapper(monkeypatch, mock_update_url):
    monkeypatch.setattr(keycloak_client_scope_crud.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_client_scope_crud.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'present',
        'client_scopes_name': 'new-client-scope-saml',
        'client_scopes_uuid': '123-123',
        'description': 'another description',
        'display_on_consent_screen': False,
        'consent_screen_text': 'Some text for consent screen',
        'protocol': 'saml',
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_client_scope_crud.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == 'Client scopes 123-123 updated.'
    assert ansible_exit_json['changed']
    assert ansible_exit_json['client_scopes'] == {
        'id': '123-123',
        'name': 'new-client-scope-saml',
        'description': 'another description',
        'protocol': 'saml',
        'attributes': {
            'display.on.consent.screen': False,
            'consent.screen.text': 'Some text for consent screen',
        },
    }


def test_no_value_changed_should_not_doing_something(monkeypatch, mock_update_url):
    monkeypatch.setattr(keycloak_client_scope_crud.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_client_scope_crud.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'present',
        'client_scopes_name': 'client_scope_with_open_id',
        'description': 'OpenID Connect built-in scope: address',
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_client_scope_crud.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == (
        'Client scopes client_scope_with_open_id up to date, doing nothing.'
    )
    assert not ansible_exit_json['changed']
    assert ansible_exit_json['client_scopes'] == {
        'id': '456-456',
        'name': 'client_scope_with_open_id',
        'description': 'OpenID Connect built-in scope: address',
        'protocol': 'openid-connect',
        'attributes': {
            'include.in.token.scope': True,
            'display.on.consent.screen': True,
            'consent.screen.text': '${addressScopeConsentText}',
        },
    }


@pytest.fixture()
def mock_url_for_saml_update(mocker):
    updated_scope = deepcopy(CONNECTION_DICT)
    updated_scope.update(
        {
            'http://keycloak.url/auth/admin/realms/master/client-scopes': create_wrapper(
                json.dumps([CLIENT_SCOPES_SAML_DICT])
            )
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), updated_scope),
        autospec=True,
    )


@pytest.mark.parametrize(
    'extra_arguments',
    [{'include_in_token_scope': True}, {'include_in_token_scope': False}],
    ids=['value true', 'value false'],
)
def test_updating_a_saml_client_scope_with_include_in_token_scope_should_fail(
    monkeypatch, mock_url_for_saml_update, extra_arguments
):
    monkeypatch.setattr(keycloak_client_scope_crud.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_client_scope_crud.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'present',
        'client_scopes_name': 'client_scope_with_saml',
    }
    arguments.update(extra_arguments)
    set_module_args(arguments)

    with pytest.raises(AnsibleFailJson) as exec_error:
        keycloak_client_scope_crud.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == (
        'include_in_token_scope should not be used whith a saml client scope'
    )
    assert not ansible_exit_json['changed']
    assert ansible_exit_json['client_scopes'] == {}


@pytest.fixture()
def mock_update_without_same_name(mocker):
    updated_scope = deepcopy(CONNECTION_DICT)
    updated_scope.update(
        {
            'http://keycloak.url/auth/admin/realms/master/client-scopes': create_wrapper(
                json.dumps([CLIENT_SCOPES_SAML_DICT, CLIENT_SCOPES_OPENID_DICT])
            ),
            'http://keycloak.url/auth/admin/realms/master/client-scopes/123-123': create_wrapper(
                json.dumps(CLIENT_SCOPES_SAML_DICT)
            ),
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), updated_scope),
        autospec=True,
    )


def test_updating_name_with_existing_name_should_raise_an_error(
    monkeypatch, mock_update_without_same_name
):
    monkeypatch.setattr(keycloak_client_scope_crud.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_client_scope_crud.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'present',
        'client_scopes_name': 'client_scope_with_open_id',
        'client_scopes_uuid': '123-123',
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleFailJson) as exec_error:
        keycloak_client_scope_crud.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == (
        'Cannot update client scopes 123-123 with client_scope_with_open_id because it '
        'already exists'
    )
    assert not ansible_exit_json['changed']
    assert ansible_exit_json['client_scopes'] == {}


@pytest.fixture()
def mock_url_update_from_name(mocker):
    updated_scope = deepcopy(CONNECTION_DICT)
    updated_client_scope = deepcopy(CLIENT_SCOPES_SAML_DICT)
    updated_client_scope.update({'description': 'a new one'})
    updated_scope.update(
        {
            'http://keycloak.url/auth/admin/realms/master/client-scopes': create_wrapper(
                json.dumps([CLIENT_SCOPES_SAML_DICT])
            ),
            'http://keycloak.url/auth/admin/realms/master/client-scopes/123-123': {
                'PUT': create_wrapper(json.dumps({})),
                'GET': create_wrapper(json.dumps(updated_client_scope)),
            },
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), updated_scope),
        autospec=True,
    )


def test_update_from_name_should_not_check_existing_name(monkeypatch, mock_url_update_from_name):
    monkeypatch.setattr(keycloak_client_scope_crud.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_client_scope_crud.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'present',
        'client_scopes_name': 'client_scope_with_saml',
        'description': 'a new one',
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_client_scope_crud.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == 'Client scopes client_scope_with_saml updated.'
    assert ansible_exit_json['changed']
    assert ansible_exit_json['client_scopes'] == {
        'id': '123-123',
        'name': 'client_scope_with_saml',
        'description': 'a new one',
        'protocol': 'saml',
        'attributes': {
            'consent.screen.text': '${samlRoleListScopeConsentText}',
            'display.on.consent.screen': True,
        },
    }
