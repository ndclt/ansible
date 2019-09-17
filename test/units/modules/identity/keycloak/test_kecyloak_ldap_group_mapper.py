# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
from copy import deepcopy
from itertools import count

import pytest
from ansible.module_utils.identity.keycloak.utils import clean_payload_with_config
from ansible.modules.identity.keycloak import keycloak_ldap_group_mapper
from ansible.module_utils.six import StringIO
from units.modules.utils import (
    AnsibleExitJson,
    AnsibleFailJson,
    fail_json,
    exit_json,
    set_module_args,
)

MAPPER_DICT = {
    'config': {
        'groups.dn': ['ou=Group,dc=my-company,dc=io'],
        'group.name.ldap.attribute': ['cn'],
        'group.object.classes': ['groupOfNames'],
        'preserve.group.inheritance': ['true'],
        'ignore.missing.groups': ['false'],
        'membership.ldap.attribute': ['member'],
        'membership.attribute.type': ['DN'],
        'membership.user.ldap.attribute': ['cn'],
        'mode': ['LDAP_ONLY'],
        'user.roles.retrieve.strategy': ['LOAD_GROUPS_BY_MEMBER_ATTRIBUTE'],
        'memberof.ldap.attribute': [''],
        'drop.non.existing.groups.during.sync': ['false'],
    },
    'name': 'group-ldap-mapper1',
    'providerId': 'group-ldap-mapper',
    'providerType': 'org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
    'parentId': '456-456',
    'id': '123-123',
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
    monkeypatch.setattr(keycloak_ldap_group_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_group_mapper.AnsibleModule, 'fail_json', fail_json)
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
        keycloak_ldap_group_mapper.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert (
        ansible_exit_json['msg']
        == 'With mapper name, the federation_id or federation_uuid must be given.'
    )
    assert not ansible_exit_json['changed']
    assert not ansible_exit_json['group_mapper']


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
    monkeypatch.setattr(keycloak_ldap_group_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_group_mapper.AnsibleModule, 'fail_json', fail_json)
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
        keycloak_ldap_group_mapper.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert (
        ansible_exit_json['msg']
        == 'Cannot access mapper because does-not-exist federation does not exist.'
    )
    assert not ansible_exit_json['changed']
    assert not ansible_exit_json['group_mapper']


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
            'http://keycloak.url/auth/admin/realms/master/components?parent=456-456&type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper&name=group-ldap-mapper1': create_wrapper(
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
    monkeypatch.setattr(keycloak_ldap_group_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_group_mapper.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'federation_id': 'my-company-ldap',
        'mapper_name': 'group-ldap-mapper1',
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleFailJson) as exec_error:
        keycloak_ldap_group_mapper.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert (
            ansible_exit_json['msg']
            == 'group-ldap-mapper1 is not a group mapper.'
    )
    assert not ansible_exit_json['changed']
    assert not ansible_exit_json['group_mapper']


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
            'http://keycloak.url/auth/admin/realms/master/components?parent=456-456&type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper&name=group-ldap-mapper1': create_wrapper(
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
        {'mapper_name': 'group-ldap-mapper1', 'federation_id': 'my-company-ldap'},
        {'mapper_uuid': '123-123'},
    ],
    ids=['mapper and federation names', 'mapper uuid'],
)
def test_present_group_mapper_without_properties_should_do_nothing(
    monkeypatch, extra_arguments, mock_existing_mapper
):
    monkeypatch.setattr(keycloak_ldap_group_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_group_mapper.AnsibleModule, 'fail_json', fail_json)
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
        keycloak_ldap_group_mapper.run_module()
    ansible_exit_json = exec_error.value.args[0]
    try:
        given_id = extra_arguments['mapper_name']
    except KeyError:
        given_id = extra_arguments['mapper_uuid']
    assert ansible_exit_json['msg'] == 'Group mapper {} up to date, doing nothing.'.format(
        given_id
    )
    assert not ansible_exit_json['changed']
    assert ansible_exit_json['group_mapper'] == {
        'name': 'group-ldap-mapper1',
        'providerId': 'group-ldap-mapper',
        'providerType': 'org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
        'parentId': '456-456',
        'id': '123-123',
        'config': {
            'groups.dn': 'ou=Group,dc=my-company,dc=io',
            'group.name.ldap.attribute': 'cn',
            'group.object.classes': 'groupOfNames',
            'preserve.group.inheritance': 'true',
            'ignore.missing.groups': 'false',
            'membership.ldap.attribute': 'member',
            'membership.attribute.type': 'DN',
            'membership.user.ldap.attribute': 'cn',
            'mode': 'LDAP_ONLY',
            'user.roles.retrieve.strategy': 'LOAD_GROUPS_BY_MEMBER_ATTRIBUTE',
            'memberof.ldap.attribute': '',
            'drop.non.existing.groups.during.sync': 'false',
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
            'http://keycloak.url/auth/admin/realms/master/components?parent=456-456&type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper&name=group-ldap-mapper1': create_wrapper(
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
    monkeypatch.setattr(keycloak_ldap_group_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_group_mapper.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'mapper_name': 'group-ldap-mapper1',
        'federation_id': 'my-company-ldap',
        'state': 'absent',
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_ldap_group_mapper.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == 'Group mapper group-ldap-mapper1 deleted.'
    assert ansible_exit_json['changed']
    assert not ansible_exit_json['group_mapper']
    delete_call = mock_delete_url.mock_calls[3]
    assert delete_call[2]['method'] == 'DELETE'


@pytest.fixture()
def mock_update_url(mocker):
    existing_federation = deepcopy(CONNECTION_DICT)
    updated_mapper = deepcopy(MAPPER_DICT)
    updated_mapper['config']['groups.dn'] = ['ou=Group,dc=NewCompany,dc=io']
    updated_mapper['config']['groups.ldap.filter'] = ['']
    updated_mapper['config']['mapped.group.attributes'] = ['']
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
            'http://keycloak.url/auth/admin/realms/master/components?parent=456-456&type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper&name=group-ldap-mapper1': create_wrapper(
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
    monkeypatch.setattr(keycloak_ldap_group_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_group_mapper.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'mapper_name': 'group-ldap-mapper1',
        'federation_id': 'my-company-ldap',
        'groups_dn': 'ou=Group,dc=NewCompany,dc=io',
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as exec_error:
        keycloak_ldap_group_mapper.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert ansible_exit_json['msg'] == 'Group mapper group-ldap-mapper1 updated.'
    assert ansible_exit_json['changed']
    update_call_arguments = json.loads(mock_update_url.mock_calls[3][2]['data'])
    reference_arguments = {
        'config': {
            'groups.dn': ['ou=Group,dc=NewCompany,dc=io'],
            'group.name.ldap.attribute': ['cn'],
            'group.object.classes': ['groupOfNames'],
            'preserve.group.inheritance': ['true'],
            'groups.ldap.filter': [''],
            'ignore.missing.groups': ['false'],
            'mapped.group.attributes': [''],
            'membership.ldap.attribute': ['member'],
            'membership.attribute.type': ['DN'],
            'membership.user.ldap.attribute': ['cn'],
            'mode': ['LDAP_ONLY'],
            'user.roles.retrieve.strategy': ['LOAD_GROUPS_BY_MEMBER_ATTRIBUTE'],
            'memberof.ldap.attribute': [''],
            'drop.non.existing.groups.during.sync': ['false'],
        },
        'name': 'group-ldap-mapper1',
        'providerId': 'group-ldap-mapper',
        'parentId': '456-456',
        'providerType': 'org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
    }
    assert update_call_arguments == reference_arguments
    reference_arguments['id'] = '123-123'
    assert ansible_exit_json['group_mapper'] == clean_payload_with_config(reference_arguments)


@pytest.mark.parametrize(
    'extra_arguments, waited_error',
    [
        (
            {'preserve_group_inheritance': 'yes', 'membership_attribute_type': 'UID'},
            'Not possible to preserve group inheritance and use UID membership type together.',
        ),
        (
            {
                'member_of_ldap_attribute': 'plop',
                'user_groups_retrieve_strategy': 'LOAD_GROUPS_BY_MEMBER_ATTRIBUTE',
            },
            (
                'member of ldap attribute is only useful when user groups strategy is get groups '
                'from user member of attribute.'
            ),
        ),
        (
            {'groups_ldap_filter': 'without parenthesis'},
            'LDAP filter should begin with a opening bracket and end with closing braket.',
        ),
    ],
    ids=[
        'inheritance and membership attribute type',
        'retrieve strategy and member of ldap attribute',
        'LDAP filter checks',
    ],
)
def test_incompatible_arguments_should_fail(
    monkeypatch, mock_update_url, extra_arguments, waited_error
):
    monkeypatch.setattr(keycloak_ldap_group_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_group_mapper.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'mapper_name': 'group-ldap-mapper1',
        'federation_id': 'my-company-ldap',
    }
    arguments.update(extra_arguments)
    set_module_args(arguments)

    with pytest.raises(AnsibleFailJson) as exec_error:
        keycloak_ldap_group_mapper.run_module()
    ansible_exit_json = exec_error.value.args[0]
    assert not ansible_exit_json['changed']
    assert not ansible_exit_json['group_mapper']
    assert ansible_exit_json['msg'] == waited_error


@pytest.fixture()
def mock_create_url(mocker):
    created_mapper = deepcopy(MAPPER_DICT)
    created_mapper['config']['memberof.ldap.attribute'] = ['memberOf']
    created_mapper['config']['groups.ldap.filter'] = ['']
    created_mapper['config']['mapped.group.attributes'] = ['']
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
            'http://keycloak.url/auth/admin/realms/master/components?parent=456-456&type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper&name=group-ldap-mapper1': [
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
    monkeypatch.setattr(keycloak_ldap_group_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_group_mapper.AnsibleModule, 'fail_json', fail_json)
    arguments = {
        'auth_keycloak_url': 'http://keycloak.url/auth',
        'auth_username': 'test_admin',
        'auth_password': 'admin_password',
        'auth_realm': 'master',
        'realm': 'master',
        'mapper_name': 'group-ldap-mapper1',
        'federation_id': 'my-company-ldap',
        'groups_dn': 'ou=Group,dc=my-company,dc=io',
    }
    set_module_args(arguments)

    with pytest.raises(AnsibleExitJson) as ansible_stacktrace:
        keycloak_ldap_group_mapper.run_module()
    ansible_exit_json = ansible_stacktrace.value.args[0]
    reference_payload = {
        'config': {
            'groups.dn': ['ou=Group,dc=my-company,dc=io'],
            'group.name.ldap.attribute': ['cn'],
            'group.object.classes': ['groupOfNames'],
            'preserve.group.inheritance': ['true'],
            'ignore.missing.groups': ['false'],
            'membership.ldap.attribute': ['member'],
            'membership.attribute.type': ['DN'],
            'membership.user.ldap.attribute': ['cn'],
            'groups.ldap.filter': [''],
            'mode': ['LDAP_ONLY'],
            'user.roles.retrieve.strategy': ['LOAD_GROUPS_BY_MEMBER_ATTRIBUTE'],
            'memberof.ldap.attribute': ['memberOf'],
            'mapped.group.attributes': [''],
            'drop.non.existing.groups.during.sync': ['false'],
        },
        'name': 'group-ldap-mapper1',
        'providerId': 'group-ldap-mapper',
        'providerType': 'org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
        'parentId': '456-456',
    }

    assert ansible_exit_json['msg'] == 'Group mapper group-ldap-mapper1 created.'
    assert ansible_exit_json['changed']
    assert ansible_exit_json['group_mapper'] == clean_payload_with_config(reference_payload)
    create_call_arguments = json.loads(mock_create_url.mock_calls[3][2]['data'])
    assert create_call_arguments == reference_payload


@pytest.fixture()
def mock_does_not_exist_mapper(mocker):
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
    monkeypatch, mock_does_not_exist_mapper
):
    monkeypatch.setattr(keycloak_ldap_group_mapper.AnsibleModule, 'exit_json', exit_json)
    monkeypatch.setattr(keycloak_ldap_group_mapper.AnsibleModule, 'fail_json', fail_json)
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
        keycloak_ldap_group_mapper.run_module()
    ansible_exit_json = ansible_stacktrace.value.args[0]
    assert ansible_exit_json['msg'] == 'Group mapper does-not-exist does not exist, doing nothing.'
    assert not ansible_exit_json['changed']
    assert not ansible_exit_json['group_mapper']
