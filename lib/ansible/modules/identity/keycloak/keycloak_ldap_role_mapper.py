#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Nicolas Duclert <nicolas.duclert@metronlab.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1', 'status': ['preview'], 'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: keycloak_ldap_role_mapper

short_description: Allows administration of Keycloak LDAP role mapper via Keycloak API
description:
  - This module allows you to add, remove or modify Keycloak LDAP role mapper via the Keycloak API.
    It requires access to the REST API via OpenID Connect; the user connecting and the client being
    used must have the requisite access rights. In a default Keycloak installation, admin-cli
    and an admin user would work, as would a separate client definition with the scope tailored
    to your needs and a user having the expected roles.

  - When updating a LDAP role mapper federation, where possible provide the mapper ID to the
    module. This removes a lookup to the API to translate the name into the mapper ID.

  - This module has been tested against keycloak 6.0, the backward compatibility is not guaranteed. 

version_added: "2.10"
options:
  state:
    description:
      - State of the LDAP federation mapper.
      - On C(present), the role mapper will be created if it does not yet exist, or updated with the parameters you provide.
      - On C(absent), the role mapper will be removed if it exists.
    required: true
    default: present
    type: str
    choices:
      - present
      - absent

  realm:
    type: str
    description:
      - They Keycloak realm under which this LDAP role mapper resides.
    default: 'master'

  federation_id:
    description:
      - The name of the federation
      - Also called ID of the federation in the table of federations or
        the console display name in the detailed view of a federation
      - This parameter is mutually exclusive with federation_uuid and one
        of them is required by the module
    type: str

  federation_uuid:
    description:
      - The uuid of the federation
      - This parameter is mutually exclusive with federation_id and one
        of them is required by the module
    type: str
  
  mapper_name:
    description:
      - The name of the role mapper
      - This parameter is mutually exclusive with mapper_uuid and one
        of them is required by the module
    type: str
        
  mapper_uuid:
    description:
      - The uuid of the role mapper
      - This parameter is mutually exclusive with mapper_name and one
        of them is required by the module
    type: str
  
  roles_dn:
    description:
      - LDAP DN where are roles of this tree saved
      - This parameter is mandatory when creating a new LDAP role mapper
    type: str
  
  role_name_ldap_attribute:
    description:
      - Name of LDAP attribute, which is used in group objects for name and RDN of role
    type: str
  
  role_object_classes:
    description:
      - List of class of the role object
    type: list
  
  membership_ldap_attribute:
    description:
      - Name of LDAP attribute on role, which is used for membership mappings
    type: str
  
  membership_attribute_type:
    description:
      - Describe the way the members of the group are declared
      - C(DN): LDAP role has it's members declared in form of their full DN,
      - C(UID): LDAP role has it's members declared in form of pure user uids
    choices:
      - DN
      - UID
    type: str
  
  membership_user_ldap_attribute:
    description:
      - Used just if I(membership_attribute_type=UID)
      - It is name of LDAP attribute on user, which is used for membership mappings
    type: str
  
  groups_ldap_filter:
    description:
      - LDAP Filter adds additional custom filter to the whole query for retrieve LDAP roles
      - Filter must start with '(' and ends with ')'
    type: str
  
  mode:
    description:
      - Select the way role will be created or not in the Keycloak database 
      - C(LDAP_ONLY): all role mappings of users are retrieved from LDAP and saved into LDAP
      - C(READ_ONLY): read-only LDAP mode where role mappings are retrieved from both LDAP and 
        DB and merged together. New role joins are not saved to LDAP but to DB.
      - C(IMPORT): read-only LDAP mode where role mappings are retrieved from LDAP just at the 
        time when user is imported from LDAP and then they are saved to local keycloak DB.
    choices:
      - LDAP_ONLY
      - READ_ONLY
      - IMPORT
    type: str
  
  user_roles_retrieve_strategy:
    description:
      - Specify how to retrieve roles of user
      - C(LOAD_ROLES_BY_MEMBER_ATTRIBUTE): roles of user will be retrieved by sending LDAP 
        query to retrieve all roles where 'member' is our user
      - C(GET_ROLES_FROM_USER_MEMBEROF_ATTRIBUTE): roles of user will be retrieved from 
        memberOf attribute of our user. Or from the other attribute specified by 
        I(member_of_ldap_attribute)
      - C(LOAD_ROLES_BY_MEMBER_ATTRIBUTE_RECURSIVELY): applicable just in Active Directory and it
        means that roles of user will be retrieved recursively with usage of
        LDAP_MATCHING_RULE_IN_CHAIN Ldap extension.
    choices:
      - LOAD_ROLES_BY_MEMBER_ATTRIBUTE
      - GET_ROLES_FROM_USER_MEMBEROF_ATTRIBUTE
      - LOAD_ROLES_BY_MEMBER_ATTRIBUTE_RECURSIVELY
  
  memberof_ldap_attribute:
    description:
      - Used just when I(user_roles_retrieve_strategy=GET_ROLES_FROM_USER_MEMBEROF_ATTRIBUTE)
      - It specifies the name of the LDAP attribute on the LDAP user, which contains the roles, 
        which the user is member of
    type: str
  
  use_realm_roles_mapping:
    description:
      - If true, then LDAP role mappings will be mapped to realm role mappings in Keycloak. 
        Otherwise it will be mapped to client role mappings
    type: str

  client_id:
    description:
      - Client ID of client to which LDAP role mappings will be mapped
      - Applicable just if I(use_realm_roles_mapping=no)

extends_documentation_fragment:
  - keycloak

author:
  - Nicolas Duclert (@ndclt)
'''

EXAMPLES = r'''
- name: Minimal creation
  keycloak_ldap_role_mapper:
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    realm: master
    state: present
    federation_id: my-company-ldap
    mapper_name: role-mapper-for-company
    roles_dn: ou=Group,dc=MyCompany
- name: Update with all parameters
  keycloak_ldap_role_mapper:
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    realm: master
    state: present
    federation_id: my-company-ldap
    mapper_name: role-mapper-for-company
    roles_dn: ou=NewGroup,dc=MyCompany
    role_name_ldap_attribute: dn
    role_object_classes:
      - OneClass
      - AnotherRoleCLass
    membership_ldap_attribute: plop
    membership_attribute_type: UID
    membership_user_ldap_attribute: attribute
    roles_ldap_filter: (anicefilter)
    mode: READ_ONLY
    user_roles_retrieve_strategy: GET_ROLES_FROM_USER_MEMBEROF_ATTRIBUTE
    memberof_ldap_attribute: a
    use_realm_roles_mapping: no
    client_id: admin-cli
'''

RETURN = r'''
msg:
  description: Message as to what action was taken
  returned: always
  type: str
  sample: "role mapper my-group-mapper created."

changed:
  description: whether the state of the keycloak configuration change
  returned: always
  type: bool

group_mapper:
  description: the LDAP role mapper representation. Empty if the asked role mapper is deleted or does not exist.
  returned: always
  type: dict
  contains:
    name:
      description: name of the LDAP role mapper
      type: str
      returned: on success
      sample: group-ldap-mapper1
    providerId:
      description: the id of the role mapper, always C(role-ldap-mapper) for this module
      type: str
      returned: on success
      sample: role-ldap-mapper
    parentId:
      description: the LDAP role mapper parent uuid
      type: str
      returned: on success
      sample: de455375-6900-46a0-8d11-51554e1c3f18
    providerType:
      description: the type of the object, for this module always C(org.keycloak.storage.ldap.mappers.LDAPStorageMapper)
      type: str
      returned: on success
      sample: org.keycloak.storage.ldap.mappers.LDAPStorageMapper
    config:
      description: the configuration of the LDAP role mapper
      type: dict
      returned: on success
      contains:
        roles.dn:
          description: LDAP DN where are roles of this tree saved
          type: str
          returned: on success
          sample: ou=Role,dc=NewCompany
        role.name.ldap.attribute:
          description: Name of LDAP attribute, which is used in role objects for name and RDN of role
          type: str
          returned: on success
          sample: cn
        role.object.classes:
          description: List of class of the role object
          type: str
          returned: on success
          sample: roleOfNames
        membership.ldap.attribute:
          description: specifies the name of the LDAP attribute on the LDAP user
          type: str
          returned: on success
          sample: memberOf
        membership.attribute.type:
          description: Describe the way the members of the role are declared
          type: str
          returned: on success
          sample: DN
        membership.user.ldap.attribute:
          description: specifies the name of the LDAP attribute on the LDAP user
          type: str
          returned: on success
          sample: memberOf
        groups.ldap.filter:
          description: LDAP Filter adds additional custom filter to the whole query for retrieve LDAP roles
          type: str
          returned: on success
          sample: (roleType=2147483652)
        mode:
          description: Select the way group will be created or not in the Keycloak database
          type: str
          returned: on success
          sample: READ_ONLY
        user.roles.retrieve.strategy:
          description: Specify how to retrieve roles of user
          type: str
          returned: on success
          sample: LOAD_GROUPS_BY_MEMBER_ATTRIBUTE
        memberof.ldap.attribute:
          description: specifies the name of the LDAP attribute on the LDAP user
          type: str
          returned: on success
          sample: memberOf
        use.realm.roles.mapping:
          description: If true, then LDAP role mappings will be mapped to realm role mappings in Keycloak. Otherwise it will be mapped to client role mappings
          type: str
          returned: on success
          sample: true
        client.id:
          description: Client ID of client to which LDAP role mappings will be mapped. Applicable just if use.realm.roles.mapping is False.
          type: str
          returned: on success
          sample: admin-cli 
'''

from ansible.module_utils.identity.keycloak.keycloak import (
    KeycloakError,
    keycloak_argument_spec,
    get_token,
)
from ansible.module_utils.common.dict_transformations import dict_merge

from ansible.module_utils.identity.keycloak.crud import crud_with_instance
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.identity.keycloak.keycloak import KeycloakAPI
from ansible.module_utils.identity.keycloak.keycloak_ldap_mapper import FederationMapper
from ansible.module_utils.identity.keycloak.utils import (
    snake_to_point_case,
    if_absent_add_a_default_value,
)


class FederationRoleMapper(FederationMapper):
    def __init__(self, module, connection_header):
        super(FederationRoleMapper, self).__init__(
            module=module, connection_header=connection_header, mapper_type='role'
        )

    def _create_payload(self):
        translation = {'mapper_name': 'name', 'mapper_uuid': 'id'}
        config = {}
        payload = {
            'providerId': 'role-ldap-mapper',
            'providerType': 'org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
        }
        not_mapper_argument = list(keycloak_argument_spec().keys()) + [
            'state',
            'realm',
            'federation_id',
        ]
        if self.federation:
            payload.update({'parentId': self.federation.uuid})
        for key, value in self.module.params.items():
            if value is not None and key not in not_mapper_argument:
                if key in list(translation.keys()):
                    payload.update({translation[key]: value})
                elif key == 'role_object_classes':
                    config.update({snake_to_point_case(key): [','.join(value)]})
                else:
                    config.update({snake_to_point_case(key): [value]})
        try:
            old_configuration = {
                key: [value] for key, value in self.initial_representation['config'].items()
            }
        except KeyError:
            old_configuration = {}
        new_configuration = dict_merge(old_configuration, config)
        self._check_arguments(new_configuration)
        dict_of_default = {
            'role.name.ldap.attribute': 'cn',
            'role.object.classes': 'groupOfNames',
            'membership.ldap.attribute': 'member',
            'membership.attribute.type': 'DN',
            'membership.user.ldap.attribute': 'cn',
            'mode': 'LDAP_ONLY',
            'user.roles.retrieve.strategy': 'LOAD_ROLES_BY_MEMBER_ATTRIBUTE',
            'memberof.ldap.attribute': 'memberOf',
            'use.realm.roles.mapping': 'true',
        }
        payload.update(
            {'config': if_absent_add_a_default_value(new_configuration, dict_of_default)}
        )
        return payload

    def _check_arguments(self, new_configuration):
        try:
            ldap_filter = new_configuration[snake_to_point_case('roles_ldap_filter')][0].strip()
        except KeyError:
            pass
        else:
            if ldap_filter[0] != '(' and ldap_filter[-1] != ')':
                raise KeycloakError(
                    'LDAP filter should begin with a opening bracket and end with closing bracket.'
                )
        try:
            client_id = new_configuration[snake_to_point_case('client_id')][0]
        except KeyError:
            pass
        else:
            keycloak_api = KeycloakAPI(self.module, self.restheaders)
            client_ids = [
                client['clientId']
                for client in keycloak_api.get_clients(self.module.params.get('realm'))
            ]
            if client_id and client_id not in client_ids:
                raise KeycloakError(
                    'Client {client_id} does not exist in the realm and cannot be used.'.format(
                        client_id=client_id
                    )
                )

    def create(self, check=False):
        if not self.module.params.get('roles_dn'):
            raise KeycloakError('roles_dn is mandatory for role mapper creation.')
        super(FederationRoleMapper, self).create(check)


def run_module():
    meta_args = dict(
        realm=dict(type='str', default='master'),
        federation_id=dict(type='str'),
        federation_uuid=dict(type='str'),
        mapper_name=dict(type='str'),
        mapper_uuid=dict(type='str'),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        roles_dn=dict(type='str'),
        role_name_ldap_attribute=dict(type='str'),
        role_object_classes=dict(type='list'),
        membership_ldap_attribute=dict(type='str'),
        membership_attribute_type=dict(type='str', choices=['DN', 'UID']),
        membership_user_ldap_attribute=dict(type='str'),
        roles_ldap_filter=dict(type='str'),
        mode=dict(type='str', choices=['LDAP_ONLY', 'IMPORT', 'READ_ONLY']),
        user_roles_retrieve_strategy=dict(
            type='str',
            choices=[
                'LOAD_ROLES_BY_MEMBER_ATTRIBUTE',
                'GET_ROLES_FROM_USER_MEMBEROF_ATTRIBUTE',
                'LOAD_ROLES_BY_MEMBER_ATTRIBUTE_RECURSIVELY',
            ],
        ),
        memberof_ldap_attribute=dict(
            type=str
        ),
        use_realm_roles_mapping=dict(type=bool),
        client_id=dict(type=str),
    )
    argument_spec = keycloak_argument_spec()
    argument_spec.update(meta_args)

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_one_of=[['mapper_name', 'mapper_uuid']],
        mutually_exclusive=[['mapper_name', 'mapper_uuid']],
    )
    if module.params.get('mapper_name') and not (
        module.params.get('federation_id') or module.params.get('federation_uuid')
    ):
        module.fail_json(
            msg='With mapper name, the federation_id or federation_uuid must be given.',
            changed=False,
            role_mapper={},
        )
    try:
        connection_header = get_token(
            base_url=module.params.get('auth_keycloak_url'),
            validate_certs=module.params.get('validate_certs'),
            auth_realm=module.params.get('auth_realm'),
            client_id=module.params.get('auth_client_id'),
            auth_username=module.params.get('auth_username'),
            auth_password=module.params.get('auth_password'),
            client_secret=module.params.get('auth_client_secret'),
        )
        role_mapper = FederationRoleMapper(module, connection_header)
        result = crud_with_instance(role_mapper, 'role_mapper')
    except KeycloakError as err:
        module.fail_json(msg=str(err), changed=False, role_mapper={})

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
