# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

from ansible.module_utils.identity.keycloak.utils import clean_payload_with_config

__metaclass__ = type

from ansible.module_utils.six import StringIO

import json
from copy import deepcopy
from itertools import count

import pytest
from units.modules.utils import (
    AnsibleExitJson,
    AnsibleFailJson,
    fail_json,
    exit_json,
    set_module_args,
)
from ansible.modules.identity.keycloak import keycloak_ldap_role_mapper

MAPPER_DICT = {
    'id': '123-123',
    'name': 'role-ldap-mapper1',
    'providerId': 'role-ldap-mapper',
    'providerType': 'org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
    'parentId': '456-456',
    'config': {
        'mode': ['LDAP_ONLY'],
        'membership.attribute.type': ['DN'],
        'user.roles.retrieve.strategy': ['LOAD_ROLES_BY_MEMBER_ATTRIBUTE'],
        'roles.dn': ['ou=oneRole,dc=my-company'],
        'membership.user.ldap.attribute': ['cn'],
        'membership.ldap.attribute': ['member'],
        'role.name.ldap.attribute': ['cn'],
        'memberof.ldap.attribute': ['memberOf'],
        'use.realm.roles.mapping': ['true'],
        'role.object.classes': ['groupOfNames'],
    },
}

WRONG_TYPE_MAPPER_DICT = deepcopy(MAPPER_DICT)
WRONG_TYPE_MAPPER_DICT.update({'providerId': 'group-ldap-mapper'})


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
    monkeypatch.setattr(keycloak_ldap_role_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_role_mapper.AnsibleModule, 'fail_json', fail_json)
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
        keycloak_ldap_role_mapper.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert (
        ansible_exit_json['msg']
        == 'With mapper name, the federation_id or federation_uuid must be given.'
    )
    assert not ansible_exit_json['changed']
    assert not ansible_exit_json['role_mapper']


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
    monkeypatch.setattr(keycloak_ldap_role_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_role_mapper.AnsibleModule, 'fail_json', fail_json)
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
        keycloak_ldap_role_mapper.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert (
        ansible_exit_json['msg']
        == 'Cannot access mapper because does-not-exist federation does not exist.'
    )
    assert not ansible_exit_json['changed']
    assert not ansible_exit_json['role_mapper']


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
            'http://keycloak.url/auth/admin/realms/master/components?parent=456-456&type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper&name=role-ldap-mapper1': create_wrapper(
                json.dumps(WRONG_TYPE_MAPPER_DICT)
            ),
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), existing_federation),
        autospec=True,
    )


def test_good_name_but_wrong_type_should_raise_an_error(monkeypatch, mock_wrong_type):
    monkeypatch.setattr(keycloak_ldap_role_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_role_mapper.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'federation_id': 'my-company-ldap',
        'mapper_name': 'role-ldap-mapper1',
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleFailJson) as exec_error:
        keycloak_ldap_role_mapper.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == 'role-ldap-mapper1 is not a role mapper.'
    assert not ansible_exit_json['changed']
    assert not ansible_exit_json['role_mapper']


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
            'http://keycloak.url/auth/admin/realms/master/components?parent=456-456&type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper&name=role-ldap-mapper1': create_wrapper(
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
        {'mapper_name': 'role-ldap-mapper1', 'federation_id': 'my-company-ldap'},
        {'mapper_uuid': '123-123'},
    ],
    ids=['mapper and federation names', 'mapper uuid'],
)
def test_present_group_mapper_without_properties_should_do_nothing(
    monkeypatch, extra_arguments, mock_existing_mapper
):
    monkeypatch.setattr(keycloak_ldap_role_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_role_mapper.AnsibleModule, 'fail_json', fail_json)
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
        keycloak_ldap_role_mapper.run_module()
    ansible_exit_json = exec_error.value.args[0]
    try:
        given_id = extra_arguments['mapper_name']
    except KeyError:
        given_id = extra_arguments['mapper_uuid']
    assert ansible_exit_json['msg'] == 'Role mapper {} up to date, doing nothing.'.format(given_id)
    assert not ansible_exit_json['changed']
    assert ansible_exit_json['role_mapper'] == {
        'id': '123-123',
        'name': 'role-ldap-mapper1',
        'providerId': 'role-ldap-mapper',
        'providerType': 'org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
        'parentId': '456-456',
        'config': {
            'mode': 'LDAP_ONLY',
            'membership.attribute.type': 'DN',
            'user.roles.retrieve.strategy': 'LOAD_ROLES_BY_MEMBER_ATTRIBUTE',
            'roles.dn': 'ou=oneRole,dc=my-company',
            'membership.user.ldap.attribute': 'cn',
            'membership.ldap.attribute': 'member',
            'role.name.ldap.attribute': 'cn',
            'memberof.ldap.attribute': 'memberOf',
            'use.realm.roles.mapping': 'true',
            'role.object.classes': 'groupOfNames',
        },
    }


@pytest.fixture()
def mock_delete_url(mocker):
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
            'http://keycloak.url/auth/admin/realms/master/components?parent=456-456&type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper&name=role-ldap-mapper1': create_wrapper(
                json.dumps(MAPPER_DICT)
            ),
            'http://keycloak.url/auth/admin/realms/master/components/123-123': create_wrapper(
                json.dumps({})
            ),
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), existing_federation),
        autospec=True,
    )


def test_state_absent_should_delete_existing_mapper(monkeypatch, mock_delete_url):
    monkeypatch.setattr(keycloak_ldap_role_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_role_mapper.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'mapper_name': 'role-ldap-mapper1',
        'federation_id': 'my-company-ldap',
        'state': 'absent',
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_ldap_role_mapper.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == 'Role mapper role-ldap-mapper1 deleted.'
    assert ansible_exit_json['changed']
    assert not ansible_exit_json['role_mapper']
    delete_call = mock_delete_url.mock_calls[3]
    assert delete_call[2]['method'] == 'DELETE'


@pytest.fixture()
def mock_update_url(mocker):
    existing_federation = deepcopy(CONNECTION_DICT)
    updated_mapper = deepcopy(MAPPER_DICT)
    updated_mapper['config']['roles.dn'] = ['ou=Role,dc=NewCompany,dc=io']
    updated_mapper['config']['role.name.ldap.attribute'] = ['bn']
    updated_mapper['config']['role.object.classes'] = ['Plop,Glop']
    updated_mapper['config']['membership.ldap.attribute'] = ['InvisibleMember']
    updated_mapper['config']['membership.attribute.type'] = ['UID']
    updated_mapper['config']['membership.user.ldap.attribute'] = ['bn']
    updated_mapper['config']['roles.ldap.filter'] = ['(abc)']
    updated_mapper['config']['mode'] = ['READ_ONLY']
    updated_mapper['config']['user.roles.retrieve.strategy'] = [
        'LOAD_ROLES_BY_MEMBER_ATTRIBUTE_RECURSIVELY'
    ]
    updated_mapper['config']['memberof.ldap.attribute'] = ['InvisibleMemberOf']
    updated_mapper['config']['use.realm.roles.mapping'] = ['true']
    updated_mapper['config']['client.id'] = ['']
    updated_mapper['id'] = '123-123'
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
            'http://keycloak.url/auth/admin/realms/master/components?parent=456-456&type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper&name=role-ldap-mapper1': create_wrapper(
                json.dumps(MAPPER_DICT)
            ),
            'http://keycloak.url/auth/admin/realms/master/components/123-123': [
                create_wrapper(json.dumps({})),
                create_wrapper(json.dumps(updated_mapper)),
            ],
            'http://keycloak.url/auth/admin/realms/master/clients': create_wrapper(
                json.dumps(
                    # This is not the full return dictionary, there is only the used key.
                    [{'clientId': 'admin-cli'}, {'clientId': 'broker'}, {'clientId': 'account'}]
                )
            ),
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), existing_federation),
        autospec=True,
    )


def test_state_present_should_update_existing_mapper(monkeypatch, mock_update_url):
    monkeypatch.setattr(keycloak_ldap_role_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_role_mapper.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'mapper_name': 'role-ldap-mapper1',
        'federation_id': 'my-company-ldap',
        'roles_dn': 'ou=Role,dc=NewCompany,dc=io',
        'role_name_ldap_attribute': 'bn',
        'role_object_classes': ['Plop', 'Glop'],
        'membership_ldap_attribute': 'InvisibleMember',
        'membership_attribute_type': 'UID',
        'membership_user_ldap_attribute': 'bn',
        'roles_ldap_filter': '(abc)',
        'mode': 'READ_ONLY',
        'user_roles_retrieve_strategy': 'LOAD_ROLES_BY_MEMBER_ATTRIBUTE_RECURSIVELY',
        'memberof_ldap_attribute': 'InvisibleMemberOf',
        'use_realm_roles_mapping': True,
        'client_id': '',
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_ldap_role_mapper.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == 'Role mapper role-ldap-mapper1 updated.'
    assert ansible_exit_json['changed']
    update_call_arguments = json.loads(mock_update_url.mock_calls[5][2]['data'])
    reference_arguments = {
        'name': 'role-ldap-mapper1',
        'providerId': 'role-ldap-mapper',
        'providerType': 'org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
        'parentId': '456-456',
        'config': {
            'roles.dn': ['ou=Role,dc=NewCompany,dc=io'],
            'role.name.ldap.attribute': ['bn'],
            'role.object.classes': ['Plop,Glop'],
            'membership.ldap.attribute': ['InvisibleMember'],
            'membership.attribute.type': ['UID'],
            'membership.user.ldap.attribute': ['bn'],
            'roles.ldap.filter': ['(abc)'],
            'mode': ['READ_ONLY'],
            'user.roles.retrieve.strategy': ['LOAD_ROLES_BY_MEMBER_ATTRIBUTE_RECURSIVELY'],
            'memberof.ldap.attribute': ['InvisibleMemberOf'],
            'use.realm.roles.mapping': [True],
            'client.id': [''],
        },
    }
    assert update_call_arguments == reference_arguments
    reference_arguments['id'] = '123-123'
    reference_arguments['config']['use.realm.roles.mapping'] = ['true']
    assert ansible_exit_json['role_mapper'] == clean_payload_with_config(reference_arguments)


@pytest.mark.parametrize(
    'extra_arguments, waited_error',
    [
        (
            {'roles_ldap_filter': 'without parenthesis'},
            'LDAP filter should begin with a opening bracket and end with closing bracket.',
        ),
        (
            {'client_id': 'does-not-exist-in-realm'},
            'Client does-not-exist-in-realm does not exist in the realm and cannot be used.',
        ),
    ],
    ids=['LDAP filter checks', 'Client does not exist'],
)
def test_incompatible_arguments_should_fail(
    monkeypatch, mock_update_url, extra_arguments, waited_error
):
    monkeypatch.setattr(keycloak_ldap_role_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_role_mapper.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'mapper_name': 'role-ldap-mapper1',
        'federation_id': 'my-company-ldap',
    }
    arguments.update(extra_arguments)
    set_module_args(arguments)

    with pytest.raises(AnsibleFailJson) as exec_error:
        keycloak_ldap_role_mapper.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert not ansible_exit_json['changed']
    assert not ansible_exit_json['role_mapper']
    assert ansible_exit_json['msg'] == waited_error


@pytest.fixture()
def mock_create_url(mocker):
    created_mapper = deepcopy(MAPPER_DICT)
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
            'http://keycloak.url/auth/admin/realms/master/components?parent=456-456&type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper&name=role-ldap-mapper1': [
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
    monkeypatch.setattr(keycloak_ldap_role_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_role_mapper.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'mapper_name': 'role-ldap-mapper1',
        'federation_id': 'my-company-ldap',
        'roles_dn': 'ou=oneRole,dc=my-company',
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as ansible_stacktrace:
        keycloak_ldap_role_mapper.run_module()
    ansible_exit_json = ansible_stacktrace.value.args[0]
    reference_payload = {
        'config': {
            'roles.dn': ['ou=oneRole,dc=my-company'],
            'role.name.ldap.attribute': ['cn'],
            'role.object.classes': ['groupOfNames'],
            'membership.ldap.attribute': ['member'],
            'membership.attribute.type': ['DN'],
            'membership.user.ldap.attribute': ['cn'],
            'mode': ['LDAP_ONLY'],
            'user.roles.retrieve.strategy': ['LOAD_ROLES_BY_MEMBER_ATTRIBUTE'],
            'memberof.ldap.attribute': ['memberOf'],
            'use.realm.roles.mapping': ['true'],
        },
        'name': 'role-ldap-mapper1',
        'providerId': 'role-ldap-mapper',
        'providerType': 'org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
        'parentId': '456-456',
    }

    assert ansible_exit_json['msg'] == 'Role mapper role-ldap-mapper1 created.'
    assert ansible_exit_json['changed']
    reference_state = clean_payload_with_config(reference_payload)
    reference_state['id'] = '123-123'
    assert ansible_exit_json['role_mapper'] == reference_state
    create_call_arguments = json.loads(mock_create_url.mock_calls[3][2]['data'])
    assert create_call_arguments == reference_payload


def test_missing_mandatory_arguments_should_raise_an_error(mock_create_url, monkeypatch):
    monkeypatch.setattr(keycloak_ldap_role_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_role_mapper.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'mapper_name': 'role-ldap-mapper1',
        'federation_id': 'my-company-ldap',
    }
    set_module_args(arguments)
    with pytest.raises(AnsibleFailJson) as ansible_stacktrace:
        keycloak_ldap_role_mapper.run_module()
    ansible_exit_json = ansible_stacktrace.value.args[0]
    assert ansible_exit_json['msg'] == 'roles_dn is mandatory for role mapper creation.'
    assert not ansible_exit_json['changed']
    assert ansible_exit_json['role_mapper'] == {}


@pytest.fixture()
def mock_does_not_exist_url(mocker):
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
            'http://keycloak.url/auth/admin/realms/master/components?parent=456-456&type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper&name=does-not-exist': create_wrapper(
                json.dumps({})
            ),
        }
    )
    return mocker.patch(
        'ansible.module_utils.identity.keycloak.keycloak.open_url',
        side_effect=build_mocked_request(count(), existing_federation),
        autospec=True,
    )


def test_absent_state_and_mapper_does_not_exist_should_do_nothing(
    monkeypatch, mock_does_not_exist_url
):
    monkeypatch.setattr(keycloak_ldap_role_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_role_mapper.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'mapper_name': 'does-not-exist',
        'federation_id': 'my-company-ldap',
        'state': 'absent',
    }
    set_module_args(arguments)
    with pytest.raises(AnsibleExitJson) as ansible_stacktrace:
        keycloak_ldap_role_mapper.run_module()
    ansible_exit_json = ansible_stacktrace.value.args[0]
    assert ansible_exit_json['msg'] == 'Role mapper does-not-exist does not exist, doing nothing.'
    assert not ansible_exit_json['changed']
    assert ansible_exit_json['role_mapper'] == {}
