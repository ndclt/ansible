# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
from copy import deepcopy
from itertools import count

import pytest
from ansible.module_utils.identity.keycloak.utils import clean_payload_with_config
from ansible.modules.identity.keycloak import keycloak_full_name_ldap_mapper
from ansible.module_utils.six import StringIO
from units.modules.utils import (
    AnsibleExitJson,
    AnsibleFailJson,
    fail_json,
    exit_json,
    set_module_args,
)

MAPPER_DICT = {
    'id': '123-123',
    'name': 'fullname-ldap-mapper1',
    'providerId': 'full-name-ldap-mapper',
    'providerType': 'org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
    'parentId': '456-456',
    'config': {'read.only': ['false'], 'write.only': ['true'], 'ldap.full.name.attribute': ['cn']},
}


WRONG_TYPE_MAPPER = deepcopy(MAPPER_DICT)
WRONG_TYPE_MAPPER.update({'providerId': 'role-ldap-mapper'})


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


def test_mapper_name_without_federation_id_should_fail(monkeypatch):
    monkeypatch.setattr(keycloak_full_name_ldap_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_full_name_ldap_mapper.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'mapper_name': 'does-not-exist-bis',
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleFailJson) as exec_error:
        keycloak_full_name_ldap_mapper.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert (
        ansible_exit_json['msg']
        == 'With mapper name, the federation_id or federation_uuid must be given.'
    )
    assert not ansible_exit_json['changed']
    assert not ansible_exit_json['full_name_ldap_mapper']


@pytest.fixture
def mock_absent_federation_url(mocker):
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


def test_federation_does_not_exist_fail(monkeypatch, mock_absent_federation_url):
    monkeypatch.setattr(keycloak_full_name_ldap_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_full_name_ldap_mapper.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'federation_id': 'does-not-exist',
        'mapper_name': 'does-not-exist-bis',
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleFailJson) as exec_error:
        keycloak_full_name_ldap_mapper.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert (
        ansible_exit_json['msg']
        == 'Cannot access mapper because does-not-exist federation does not exist.'
    )
    assert not ansible_exit_json['changed']
    assert not ansible_exit_json['full_name_ldap_mapper']


@pytest.fixture()
def mock_wrong_type(mocker):
    existing_federation = deepcopy(CONNECTION_DICT)
    existing_federation.update(
        {
            'http://keycloak.url/auth/admin/realms/master/components?parent=master&type=org.keycloak.storage.UserStorageProvider&name=my-company-ldap': create_wrapper(
                json.dumps(
                    {
                        'id': '456-456',
                        'name': 'my-company-ldap',
                        'parentId': 'master',
                        'config': {'pagination': [True]},
                    }
                )
            ),
            'http://keycloak.url/auth/admin/realms/master/components?parent=456-456&type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper&name=fullname-ldap-mapper1': create_wrapper(
                json.dumps(WRONG_TYPE_MAPPER)
            ),
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), existing_federation),
        autospec=True,
    )


def test_good_name_but_wrong_type_should_raise_an_error(monkeypatch, mock_wrong_type):
    monkeypatch.setattr(keycloak_full_name_ldap_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_full_name_ldap_mapper.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'federation_id': 'my-company-ldap',
        'mapper_name': 'fullname-ldap-mapper1',
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleFailJson) as exec_error:
        keycloak_full_name_ldap_mapper.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == 'fullname-ldap-mapper1 is not a full name mapper.'
    assert not ansible_exit_json['changed']
    assert not ansible_exit_json['full_name_ldap_mapper']


@pytest.fixture()
def mock_existing_mapper(mocker):
    existing_federation = deepcopy(CONNECTION_DICT)
    existing_federation.update(
        {
            'http://keycloak.url/auth/admin/realms/master/components?parent=master&type=org.keycloak.storage.UserStorageProvider&name=my-company-ldap': create_wrapper(
                json.dumps(
                    {
                        'id': '456-456',
                        'name': 'my-company-ldap',
                        'parentId': 'master',
                        'config': {'pagination': [True]},
                    }
                )
            ),
            'http://keycloak.url/auth/admin/realms/master/components?parent=456-456&type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper&name=fullname-ldap-mapper1': create_wrapper(
                json.dumps(MAPPER_DICT)
            ),
            'http://keycloak.url/auth/admin/realms/master/components/123-123': create_wrapper(
                json.dumps(MAPPER_DICT)
            ),
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), existing_federation),
        autospec=True,
    )


@pytest.mark.parametrize(
    'extra_arguments',
    [
        {'mapper_name': 'fullname-ldap-mapper1', 'federation_id': 'my-company-ldap'},
        {'mapper_uuid': '123-123'},
    ],
    ids=['mapper and federation names', 'mapper uuid'],
)
def test_present_group_mapper_without_properties_should_do_nothing(
    monkeypatch, extra_arguments, mock_existing_mapper
):
    monkeypatch.setattr(keycloak_full_name_ldap_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_full_name_ldap_mapper.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
    }
    arguments.update(extra_arguments)
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_full_name_ldap_mapper.run_module()
    ansible_exit_json = exec_error.value.args[0]
    try:
        given_id = extra_arguments['mapper_name']
    except KeyError:
        given_id = extra_arguments['mapper_uuid']
    assert ansible_exit_json['msg'] == 'Full name mapper {} up to date, doing nothing.'.format(
        given_id
    )
    assert not ansible_exit_json['changed']
    assert ansible_exit_json['full_name_ldap_mapper'] == {
        'id': '123-123',
        'name': 'fullname-ldap-mapper1',
        'providerId': 'full-name-ldap-mapper',
        'providerType': 'org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
        'parentId': '456-456',
        'config': {'read.only': 'false', 'write.only': 'true', 'ldap.full.name.attribute': 'cn'},
    }


# Tests about delete is not done because already covered by other mapper.


@pytest.fixture()
def mock_update_url(mocker):
    existing_federation = deepcopy(CONNECTION_DICT)
    updated_mapper = deepcopy(MAPPER_DICT)
    updated_mapper['config']['ldap.full.name.attribute'] = ['notCn']
    existing_federation.update(
        {
            'http://keycloak.url/auth/admin/realms/master/components?parent=master&type=org.keycloak.storage.UserStorageProvider&name=my-company-ldap': create_wrapper(
                json.dumps(
                    {
                        'id': '456-456',
                        'name': 'my-company-ldap',
                        'parentId': 'master',
                        'config': {'pagination': [True]},
                    }
                )
            ),
            'http://keycloak.url/auth/admin/realms/master/components?parent=456-456&type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper&name=fullname-ldap-mapper1': create_wrapper(
                json.dumps(MAPPER_DICT)
            ),
            'http://keycloak.url/auth/admin/realms/master/components/123-123': [
                create_wrapper(json.dumps({})),
                create_wrapper(json.dumps(updated_mapper)),
            ],
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), existing_federation),
        autospec=True,
    )


def test_state_present_should_update_existing_mapper(monkeypatch, mock_update_url):
    monkeypatch.setattr(keycloak_full_name_ldap_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_full_name_ldap_mapper.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'mapper_name': 'fullname-ldap-mapper1',
        'federation_id': 'my-company-ldap',
        'ldap_full_name_attribute': 'notCn',
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_full_name_ldap_mapper.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == 'Full name mapper fullname-ldap-mapper1 updated.'
    assert ansible_exit_json['changed']
    update_call_arguments = json.loads(mock_update_url.mock_calls[3][2]['data'])
    reference_arguments = {
        'config': {
            'ldap.full.name.attribute': ['notCn'],
            'read.only': ['false'],
            'write.only': ['true'],
        },
        'name': 'fullname-ldap-mapper1',
        'parentId': '456-456',
        'providerId': 'full-name-ldap-mapper',
        'providerType': 'org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
    }
    assert update_call_arguments == reference_arguments
    reference_arguments['id'] = '123-123'
    assert ansible_exit_json['full_name_ldap_mapper'] == clean_payload_with_config(
        reference_arguments
    )


@pytest.mark.parametrize(
    'extra_arguments, waited_error',
    [({'read_only': True, 'write_only': True}, 'Cannot have read only and write only together')],
    ids=['read only and write only'],
)
def test_incompatible_arguments_should_fail(
    monkeypatch, mock_update_url, extra_arguments, waited_error
):
    monkeypatch.setattr(keycloak_full_name_ldap_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_full_name_ldap_mapper.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'mapper_name': 'fullname-ldap-mapper1',
        'federation_id': 'my-company-ldap',
    }
    arguments.update(extra_arguments)
    set_module_args(arguments)

    with pytest.raises(AnsibleFailJson) as exec_error:
        keycloak_full_name_ldap_mapper.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert not ansible_exit_json['changed']
    assert not ansible_exit_json['full_name_ldap_mapper']
    assert ansible_exit_json['msg'] == waited_error


@pytest.fixture()
def mock_create_url(mocker):
    created_mapper = deepcopy(MAPPER_DICT)
    created_mapper.pop('id')
    existing_federation = deepcopy(CONNECTION_DICT)
    existing_federation.update(
        {
            'http://keycloak.url/auth/admin/realms/master/components?parent=master&type=org.keycloak.storage.UserStorageProvider&name=my-company-ldap': create_wrapper(
                json.dumps(
                    {
                        'id': '456-456',
                        'name': 'my-company-ldap',
                        'parentId': 'master',
                        'config': {'pagination': [True]},
                    }
                )
            ),
            'http://keycloak.url/auth/admin/realms/master/components?parent=456-456&type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper&name=fullname-ldap-mapper1': [
                create_wrapper(json.dumps({})),
                create_wrapper(json.dumps(created_mapper)),
            ],
            'http://keycloak.url/auth/admin/realms/master/components': create_wrapper(
                json.dumps({})
            ),
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), existing_federation),
        autospec=True,
    )


def test_present_state_should_create_absent_mapper(monkeypatch, mock_create_url):
    monkeypatch.setattr(keycloak_full_name_ldap_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_full_name_ldap_mapper.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'mapper_name': 'fullname-ldap-mapper1',
        'federation_id': 'my-company-ldap',
        'ldap_full_name_attribute': 'cn',
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as ansible_stacktrace:
        keycloak_full_name_ldap_mapper.run_module()
    ansible_exit_json = ansible_stacktrace.value.args[0]
    reference_payload = {
        'config': {
            'ldap.full.name.attribute': ['cn'],
            'read.only': ['false'],
            'write.only': ['true'],
        },
        'name': 'fullname-ldap-mapper1',
        'parentId': '456-456',
        'providerId': 'full-name-ldap-mapper',
        'providerType': 'org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
    }

    assert ansible_exit_json['msg'] == 'Full name mapper fullname-ldap-mapper1 created.'
    assert ansible_exit_json['changed']
    assert ansible_exit_json['full_name_ldap_mapper'] == clean_payload_with_config(
        reference_payload
    )
    create_call_arguments = json.loads(mock_create_url.mock_calls[3][2]['data'])
    assert create_call_arguments == reference_payload


def test_check_mandatory_arguments_for_creation(monkeypatch, mock_create_url):
    monkeypatch.setattr(keycloak_full_name_ldap_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_full_name_ldap_mapper.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'mapper_name': 'fullname-ldap-mapper1',
        'federation_id': 'my-company-ldap',
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleFailJson) as ansible_stacktrace:
        keycloak_full_name_ldap_mapper.run_module()
    ansible_exit_json = ansible_stacktrace.value.args[0]
    assert ansible_exit_json['msg'] == (
        'ldap_full_name_attribute is mandatory for full name mapper creation.'
    )
    assert not ansible_exit_json['changed']
    assert not ansible_exit_json['full_name_ldap_mapper']

# Tests about no creation when absent is not done because already covered by other mapper.
