# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

import json
from itertools import count, filterfalse

import pytest

from ansible.module_utils.six import StringIO
from ansible.modules.identity.keycloak import keycloak_ldap_federation
from units.modules.utils import (
    AnsibleExitJson,
    AnsibleFailJson,
    fail_json,
    exit_json,
    set_module_args,
)
from ansible.module_utils._text import to_text
from ansible.module_utils.common.dict_transformations import recursive_diff
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.six.moves.urllib.parse import urlencode


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


@pytest.fixture
def mock_get_token(mocker):
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), CONNECTION_DICT),
        autospec=True,
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


def raise_404(url):
    def _raise_404():
        raise HTTPError(
            url=url, code=404, msg='does not exist', hdrs='', fp=StringIO('')
        )

    return _raise_404


@pytest.fixture
def mock_absent_url(mocker):
    absent_federation = {
        'http://keycloak.url/auth/admin/realms/master/components?parent=master&type=org.keycloak.storage.UserStorageProvider&name=not_here': create_wrapper(
            json.dumps([])
        ),
        'http://keycloak.url/auth/admin/realms/master/components?parent=master&type=org.keycloak.storage.UserStorageProvider&name=not%20here': create_wrapper(
            json.dumps([])
        ),
        'http://keycloak.url/auth/admin/realms/master/components/123-123': raise_404(
            'http://keycloak.url/auth/admin/realms/master/components/123-123'
        ),
    }
    return mocker.patch(
        'ansible.modules.identity.keycloak.keycloak_ldap_federation.open_url',
        side_effect=build_mocked_request(count(), absent_federation),
        autospec=True,
    )


@pytest.mark.parametrize(
    'extra_arguments',
    [
        {'federation_id': 'not_here'},
        {'federation_id': 'not here'},
        {'federation_uuid': '123-123'},
    ],
)
def test_state_absent_should_not_create_absent_federation(
    monkeypatch, mock_absent_url, mock_get_token, extra_arguments
):
    monkeypatch.setattr(keycloak_ldap_federation.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_federation.AnsibleModule, 'fail_json', fail_json)
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

    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_ldap_federation.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json[
        'msg'
    ] == 'Federation {} does not exist, doing nothing.'.format(
        list(extra_arguments.values())[0]
    )
    assert not ansible_exit_json['changed']
    assert not ansible_exit_json['ldap_federation']


@pytest.fixture
def mock_delete_url(mocker):
    # This fixture does not return a full federation json, just an extract
    # with parts needed in the test and some value in order to have object
    # organisation.
    delete_federation = {
        'http://keycloak.url/auth/admin/realms/master/components?parent=master&type=org.keycloak.storage.UserStorageProvider&name=ldap-to-delete': create_wrapper(
            json.dumps(
                [
                    {
                        'id': '123-123',
                        'name': 'ldap-to-delete',
                        'parentId': 'master',
                        'config': {'pagination': True},
                    }
                ]
            )
        ),
        'http://keycloak.url/auth/admin/realms/master/components/123-123': {
            'DELETE': None,
            'GET': create_wrapper(
                json.dumps(
                    {
                        'id': '123-123',
                        'name': 'ldap-to-delete',
                        'parentId': 'master',
                        'config': {'pagination': True},
                    }
                )
            ),
        },
    }
    return mocker.patch(
        'ansible.modules.identity.keycloak.keycloak_ldap_federation.open_url',
        side_effect=build_mocked_request(count(), delete_federation),
        autospec=True,
    )


@pytest.mark.parametrize(
    'extra_arguments',
    [{'federation_id': 'ldap-to-delete'}, {'federation_uuid': '123-123'}],
)
def test_state_absent_should_delete_existing_federation(
    monkeypatch, extra_arguments, mock_delete_url, mock_get_token
):
    monkeypatch.setattr(keycloak_ldap_federation.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_federation.AnsibleModule, 'fail_json', fail_json)
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

    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_ldap_federation.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == 'Federation {} deleted.'.format(
        list(extra_arguments.values())[0]
    )
    assert ansible_exit_json['changed']
    assert not ansible_exit_json['ldap_federation']


@pytest.fixture()
def mock_create_url(mocker):
    create_federation = {
        'http://keycloak.url/auth/admin/realms/master/components?parent=master&type=org.keycloak.storage.UserStorageProvider&name=company-ldap': create_wrapper(
            json.dumps([])
        ),
        'http://keycloak.url/auth/admin/realms/master/components/': None,
    }
    return mocker.patch(
        'ansible.modules.identity.keycloak.keycloak_ldap_federation.open_url',
        side_effect=build_mocked_request(count(), create_federation),
        autospec=True,
    )


def test_state_present_should_create_absent_federation(
    monkeypatch, mock_create_url, mock_get_token
):
    monkeypatch.setattr(keycloak_ldap_federation.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_federation.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'present',
        'federation_id': 'company-ldap',
        'vendor': 'other',
        'edit_mode': 'WRITABLE',
        'synchronize_registrations': True,
        'username_ldap_attribute': 'cn',
        'rdn_ldap_attribute': 'cn',
        'user_object_classes': ['inetOrgPerson', 'organizationalPerson'],
        'connection_url': 'ldap://openldap',
        'users_dn': 'ou=People,dc=my-company',
        'bind_dn': 'cn=admin,dc=my-company',
        'bind_credential': 'ldap_admin_password',
        'uuid_ldap_attribute': 'entryUUID',
        'search_scope': 'subtree',
        'use_truststore_spi': 'never',
    }
    set_module_args(arguments)
    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_ldap_federation.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == 'Federation company-ldap created.'
    assert ansible_exit_json['changed']
    reference_result = {
        'config': {
            'bindDn': 'cn=admin,dc=my-company',
            'connectionPooling': False,
            'connectionUrl': 'ldap://openldap',
            'bindCredential': 'no_log',
            'editMode': 'WRITABLE',
            'priority': 0,
            'rdnLDAPAttribute': 'cn',
            'searchScope': 2,
            'synchronizeRegistrations': True,
            'useTruststoreSpi': 'never',
            'userObjectClasses': 'inetOrgPerson, organizationalPerson',
            'usernameLDAPAttribute': 'cn',
            'usersDn': 'ou=People,dc=my-company',
            'uuidLDAPAttribute': 'entryUUID',
            'vendor': 'other',
        },
        'name': 'company-ldap',
        'providerId': 'ldap',
        'providerType': 'org.keycloak.storage.UserStorageProvider',
    }
    diff_result = recursive_diff(ansible_exit_json['ldap_federation'], reference_result)
    assert not diff_result
    config = reference_result.pop('config')
    send_config = {}
    for key, value in config.items():
        if key == 'bindCredential':
            send_config.update({'bindCredential': ['ldap_admin_password']})
        else:
            send_config.update({key: [value]})
    reference_result.update({'config': send_config})
    create_call = mock_create_url.mock_calls[1]
    send_json = json.loads(create_call.kwargs['data'])
    diff_result = recursive_diff(send_json, reference_result)
    assert not diff_result


def test_create_payload_all_mandatory(monkeypatch, mock_absent_url, mock_get_token):
    monkeypatch.setattr(keycloak_ldap_federation.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_federation.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'present',
        'federation_id': 'not_here',
    }
    set_module_args(arguments)
    with pytest.raises(AnsibleFailJson) as exec_error:
        keycloak_ldap_federation.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == (
        'bind_credential, bind_dn, connection_url, rdn_ldap_attribute, '
        'user_object_classes, username_ldap_attribute, users_dn, uuid_ldap_attribute '
        'and vendor are missing for the federation creation.'
    )


@pytest.fixture()
def mock_create_url_with_check(mocker):
    create_federation = {
        'http://keycloak.url/auth/admin/realms/master/components?parent=master&type=org.keycloak.storage.UserStorageProvider&name=company-ldap': create_wrapper(
            json.dumps([])
        ),
        'http://keycloak.url/auth/admin/realms/master/components/': None,
        'http://keycloak.url/auth/admin/realms/master/testLDAPConnection': None,
    }
    return mocker.patch(
        'ansible.modules.identity.keycloak.keycloak_ldap_federation.open_url',
        side_effect=build_mocked_request(count(), create_federation),
        autospec=True,
    )


@pytest.mark.parametrize(
    'extra_arguments',
    [{'test_connection': True}, {'test_authentication': True}],
    ids=['connection only', 'authentication'],
)
def test_arguments_check_connectivity_should_try_ldap_connection(
    monkeypatch, extra_arguments, mock_create_url_with_check, mock_get_token
):
    monkeypatch.setattr(keycloak_ldap_federation.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_federation.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'present',
        'federation_id': 'company-ldap',
        'vendor': 'other',
        'edit_mode': 'WRITABLE',
        'synchronize_registrations': True,
        'username_ldap_attribute': 'cn',
        'rdn_ldap_attribute': 'cn',
        'user_object_classes': ['inetOrgPerson', 'organizationalPerson'],
        'connection_url': 'ldap://openldap',
        'users_dn': 'ou=People,dc=my-company',
        'bind_dn': 'cn=admin,dc=my-company',
        'bind_credential': 'ldap_admin_password',
        'uuid_ldap_attribute': 'entryUUID',
    }
    arguments.update(extra_arguments)
    set_module_args(arguments)
    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_ldap_federation.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == 'Federation company-ldap created.'
    assert ansible_exit_json['changed']
    calls = mock_create_url_with_check.mock_calls
    for one_call in filterfalse(lambda x: 'testLDAPConnection' not in x.args[0], calls):
        send_data = one_call.kwargs['data']
        assert urlencode({'bindCredential': 'ldap_admin_password'}) in send_data
        assert urlencode({'bindDn': 'cn=admin,dc=my-company'}) in send_data


def raise_400(url):
    def _raise_400():
        raise HTTPError(url=url, code=400, msg='', hdrs='', fp=StringIO(''))

    return _raise_400


@pytest.fixture()
def mock_wrong_authentication_url(mocker, request):
    ldap_connection = {
        'wrong LDAP address': raise_400(
            'http://keycloak.url/auth/admin/realms/master/testLDAPConnection'
        ),
        'wrong credentials': [
            None,
            raise_400(
                'http://keycloak.url/auth/admin/realms/master/testLDAPConnection'
            ),
        ],
    }
    create_federation = {
        'http://keycloak.url/auth/admin/realms/master/components?parent=master&type=org.keycloak.storage.UserStorageProvider&name=company-ldap': create_wrapper(
            json.dumps([])
        ),
        'http://keycloak.url/auth/admin/realms/master/testLDAPConnection': ldap_connection[
            request.node.callspec.id
        ],
    }
    return mocker.patch(
        'ansible.modules.identity.keycloak.keycloak_ldap_federation.open_url',
        side_effect=build_mocked_request(count(), create_federation),
        autospec=True,
    )


@pytest.mark.parametrize(
    'extra_arguments, waited_message',
    [
        (
            {
                'connection_url': 'ldap://wrong.openldap',
                'bind_dn': 'cn=admin,dc=my-company',
                'bind_credential': 'ldap_admin_password',
            },
            'The url connection ldap://wrong.openldap cannot be reached.',
        ),
        (
            {
                'connection_url': 'ldap://openldap',
                'bind_dn': 'cn=admin,dc=my-company',
                'bind_credential': 'ldap_admin_password',
            },
            (
                'The user cn=admin,dc=my-company cannot logged in the ldap at '
                'ldap://openldap, you should check your credentials.'
            ),
        ),
    ],
    ids=['wrong LDAP address', 'wrong credentials'],
)
def test_wrong_ldap_credentials_should_raise_an_error(
    monkeypatch,
    extra_arguments,
    waited_message,
    mock_wrong_authentication_url,
    mock_get_token,
):
    monkeypatch.setattr(keycloak_ldap_federation.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_federation.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'present',
        'federation_id': 'company-ldap',
        'rdn_ldap_attribute': 'cn',
        'user_object_classes': ['inetOrgPerson', 'organizationalPerson'],
        'username_ldap_attribute': 'cn',
        'users_dn': 'ou=People,dc=my-company',
        'uuid_ldap_attribute': 'entryUUID',
        'vendor': 'other',
        'test_authentication': True,
    }
    arguments.update(extra_arguments)
    set_module_args(arguments)
    with pytest.raises(AnsibleFailJson) as exec_error:
        keycloak_ldap_federation.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == waited_message


@pytest.fixture()
def mock_update_url(mocker):
    update_federation = {
        'http://keycloak.url/auth/admin/realms/master/components?parent=master&type=org.keycloak.storage.UserStorageProvider&name=company-ldap': create_wrapper(
            json.dumps(
                [
                    {
                        'id': '123-123',
                        'name': 'company-ldap',
                        'parentId': 'master',
                        'config': {
                            'pagination': [True],
                            'bindDn': ['cn:admin'],
                        },
                    }
                ]
            )
        ),
        'http://keycloak.url/auth/admin/realms/master/components/123-123': None,
        'http://keycloak.url/auth/admin/realms/master/testLDAPConnection': None,
    }
    return mocker.patch(
        'ansible.modules.identity.keycloak.keycloak_ldap_federation.open_url',
        side_effect=build_mocked_request(count(), update_federation),
        autospec=True,
    )


def test_state_present_should_update_existing_federation(
    monkeypatch, mock_get_token, mock_update_url
):
    monkeypatch.setattr(keycloak_ldap_federation.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_federation.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'present',
        'federation_id': 'company-ldap',
        'uuid_ldap_attribute': 'newEntryUUID',
    }
    set_module_args(arguments)
    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_ldap_federation.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == 'Federation company-ldap updated.'
    assert ansible_exit_json['changed']
    reference_result = {
        'config': {
            'uuidLDAPAttribute': 'newEntryUUID',
            'priority': 0,
            'connectionPooling': False,
        },
        'name': 'company-ldap',
        'providerId': 'ldap',
        'providerType': 'org.keycloak.storage.UserStorageProvider',
    }
    diff_result = recursive_diff(ansible_exit_json['ldap_federation'], reference_result)
    assert not diff_result


def test_state_present_should_update_existing_federation_with_connect_check(
    monkeypatch, mock_get_token, mock_update_url
):
    monkeypatch.setattr(keycloak_ldap_federation.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_federation.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'state': 'present',
        'federation_id': 'company-ldap',
        'uuid_ldap_attribute': 'newEntryUUID',
        'bind_credential': 'new_admin_password',
        'test_authentication': True,
    }
    set_module_args(arguments)
    with pytest.raises(AnsibleExitJson):
        keycloak_ldap_federation.run_module()
    calls = mock_update_url.mock_calls
    for one_call in filterfalse(lambda x: 'testLDAPConnection' not in x.args[0], calls):
        send_data = one_call.kwargs['data']
        assert urlencode({'bindCredential': 'new_admin_password'}) in send_data
        assert urlencode({'bindDn': 'cn:admin'}) in send_data
