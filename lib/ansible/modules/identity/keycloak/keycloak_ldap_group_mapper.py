#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Nicolas Duclert <nicolas.duclert@metronlab.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1', 'status': ['preview'], 'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: keycloak_ldap_group_mapper

short_description: Allows administration of Keycloak LDAP group mapper via Keycloak API
description:
  - This module allows you to add, remove or modify Keycloak LDAP group mapper via the Keycloak API.
    It requires access to the REST API via OpenID Connect; the user connecting and the client being
    used must have the requisite access rights. In a default Keycloak installation, admin-cli
    and an admin user would work, as would a separate client definition with the scope tailored
    to your needs and a user having the expected roles.

  - When updating a LDAP group mapper federation, where possible provide the mapper ID to the
    module. This removes a lookup to the API to translate the name into the mapper ID.

  - This module has been tested against keycloak 6.0, the backward compatibility is not garanteed. 

version_added: "2.10"
options:
  state:
    description:
      - State of the LDAP federation.
      - On C(present), the group mapper will be created if it does not yet exist, or updated with the parameters you provide.
      - On C(absent), the group mapper will be removed if it exists.
    required: true
    default: present
    type: str
    choices:
      - present
      - absent

  realm:
    type: str
    description:
      - They Keycloak realm under which this LDAP group mapper resides.
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
      - The name of the group mapper
      - This parameter is mutually exclusive with mapper_uuid and one
        of them is required by the module
    type: str
        
  mapper_uuid:
    description:
      - The uuid of the group mapper
      - This parameter is mutually exclusive with mapper_name and one
        of them is required by the module
    type: str
        
  groups_dn:
    description:
      - LDAP DN where are groups of this tree saved
      - This parameter is mandatory when creating a new LDAP group mapper
    type: str
  
  group_name_ldap_attribute:
    description:
      - Name of LDAP attribute, which is used in group objects for name and RDN of group
    type: str
  
  group_object_classes:
    description:
      - List of class of the group object
    type: list
  
  preserve_group_inheritance:
    description:
      - Flag whether group inheritance from LDAP should be propagated to Keycloak
      - If C(no), then all LDAP groups will be mapped as flat top-level groups in Keycloak. 
        Otherwise group inheritance is preserved into Keycloak, but the group sync might fail if
        LDAP structure contains recursions or multiple parent groups per child groups
      - If C(yes), this arguments is incompatible with I(membership_attribute_type=UID)
    type: bool
  
  ignore_missing_groups:
    description:
      - Ignore missing groups in the group hierarchy
    type: bool
  
  membership_ldap_attribute:
    description:
      - Name of LDAP attribute on group, which is used for membership mappings
    type: str
  
  membership_attribute_type:
    description:
      - Describe the way the members of the group are declared
      - C(DN): LDAP group has it's members declared in form of their full DN,
      - C(UID): LDAP group has it's members declared in form of pure user uids
      - If C(UID), this arguments is incompatible with I(preserve_group_inheritance=yes)
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
      - LDAP Filter adds additional custom filter to the whole query for retrieve LDAP groups
      - Filter must start with '(' and ends with ')'
    type: str
  
  mode:
    description:
      - Select the way group will be created or not in the Keycloak database 
      - C(LDAP_ONLY): all group mappings of users are retrieved from LDAP and saved into LDAP
      - C(READ_ONLY): read-only LDAP mode where group mappings are retrieved from both LDAP and 
        DB and merged together. New group joins are not saved to LDAP but to DB.
      - C(IMPORT): read-only LDAP mode where group mappings are retrieved from LDAP just at the 
        time when user is imported from LDAP and then they are saved to local keycloak DB.
    choices:
      - LDAP_ONLY
      - READ_ONLY
      - IMPORT
    type: str
  
  user_groups_retrieve_strategy:
    description:
      - Specify how to retrieve groups of user
      - C(LOAD_GROUPS_BY_MEMBER_ATTRIBUTE): groups of user will be retrieved by sending LDAP 
        query to retrieve all groups where 'member' is our user
      - C(GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE): groups of user will be retrieved from 
        memberOf attribute of our user. Or from the other attribute specified by 
        I(member_of_ldap_attribute)
      - C(LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY): applicable just in Active Directory and it
        means that groups of user will be retrieved recursively with usage of
        LDAP_MATCHING_RULE_IN_CHAIN Ldap extension.
    choices:
      - LOAD_GROUPS_BY_MEMBER_ATTRIBUTE
      - GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE
      - LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY

  member_of_ldap_attribute:
    description:
      - Used just when I(user_groups_retrieve_strategy=GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE)
      - It specifies the name of the LDAP attribute on the LDAP user, which contains the groups, 
        which the user is member of
    type: str
  
  mapped_group_attributes:
    description:
      - This points to the list of attributes on LDAP group, which will be mapped as attributes of
        group in Keycloak.
    type: list
  
  drop_non_existing_groups_during_sync:
    description:
      - If C(yes), then during sync of groups from LDAP to Keycloak, Keycloak groups which don't
        exists in LDAP will be deleted
    type: bool
    
extends_documentation_fragment:
  - keycloak

author:
  - Nicolas Duclert (@ndclt)
'''

EXAMPLES = r'''
- name: Create a LDAP group mapper
  keycloak_ldap_group_mapper:
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    realm: master
    federation_id: my-company-ldap
    groups_dn: ou=Group,dc=MyCompany
    membership_attribute_type: DN
'''

RETURN = r'''
msg:
  description: Message as to what action was taken
  returned: always
  type: str
  sample: "Group mapper my-group-mapper created."

changed:
  description: whether the state of the keycloak configuration change
  returned: always
  type: bool

group_mapper:
  description: the LDAP group mapper representation. Empty if the asked group mapper is deleted or does not exist.
  returned: always
  type: dict
  contains:
    name:
      description: name of the LDAP group mapper
      type: str
      returned: on success
      sample: group-ldap-mapper1
    providerId:
      description: the id of the group mapper, always C(group-ldap-mapper) for this module
      type: str
      returned: on success
      sample: group-ldap-mapper
    parentId:
      description: the LDAP group mapper parent uuid
      type: str
      returned: on success
      sample: de455375-6900-46a0-8d11-51554e1c3f18
    providerType:
      description: the type of the object, for this module always C(org.keycloak.storage.ldap.mappers.LDAPStorageMapper)
      type: str
      returned: on success
      sample: org.keycloak.storage.ldap.mappers.LDAPStorageMapper
    config:
      description: the configuration of the LDAP group mapper
      type: dict
      returned: on success
      contains:
        groups.dn:
          description: LDAP DN where are groups of this tree saved
          type: str
          returned: on success
          sample: ou=Group,dc=NewCompany
        group.name.ldap.attribute:
          description: Name of LDAP attribute, which is used in group objects for name and RDN of group
          type: str
          returned: on success
          sample: cn
        group.object.classes:
          description: List of class of the group object
          type: str
          returned: on success
          sample: groupOfNames
        preserve.group.inheritance:
          description: Flag whether group inheritance from LDAP should be propagated to Keycloak
          type: bool
          returned: on success
          sample: true
        groups.ldap.filter:
          description: LDAP Filter adds additional custom filter to the whole query for retrieve LDAP groups
          type: str
          returned: on success
          sample: (groupType=2147483652)
        ignore.missing.groups:
          description: Ignore missing groups in the group hierarchy
          type: bool
          returned: on success
          sample: false
        mapped.group.attributes:
          description: This points to the list of attributes on LDAP group, which will be mapped as attributes of group in Keycloak.
          type: str
          returned: on success
          sample: attribute1, attribute2
        membership.ldap.attribute:
          description: specifies the name of the LDAP attribute on the LDAP user
          type: str
          returned: on success
          sample: memberOf
        membership.attribute.type:
          description: Describe the way the members of the group are declared
          type: str
          returned: on success
          sample: DN
        membership.user.ldap.attribute:
          description: Describe the way the members of the group are declared
          type: str
          returned: on success
          sample: DN
        mode:
          description: Select the way group will be created or not in the Keycloak database
          type: str
          returned: on success
          sample: READ_ONLY
        user.roles.retrieve.strategy:
          description: Specify how to retrieve groups of user
          type: str
          returned: on success
          sample: LOAD_GROUPS_BY_MEMBER_ATTRIBUTE
        memberof.ldap.attribute:
          description: specifies the name of the LDAP attribute on the LDAP user
          type: str
          returned: on success
          sample: memberOf
        drop.non.existing.groups.during.sync:
          description: Specify if Keycloak groups which don't exists in LDAP will be deleted
          type: str
          returned: on success
          sample: false
'''

from ansible.module_utils.common.dict_transformations import dict_merge

from ansible.module_utils.identity.keycloak.crud import crud_with_instance
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.identity.keycloak.utils import (
    if_absent_add_a_default_value,
)
from ansible.module_utils.identity.keycloak.keycloak import (
    keycloak_argument_spec,
    get_token,
    KeycloakError,
)
from ansible.module_utils.identity.keycloak.keycloak_ldap_mapper import FederationMapper

from ansible.module_utils.identity.keycloak.utils import snake_to_point_case, convert_to_bool

USER_GROUP_RETRIEVE_STRATEGY_LABEL = 'user.roles.retrieve.strategy'


class FederationGroupMapper(FederationMapper):
    def __init__(self, module, connection_header):
        super(FederationGroupMapper, self).__init__(
            module=module, connection_header=connection_header, mapper_type='group'
        )

    def _create_payload(self):
        translation = {'mapper_name': 'name', 'mapper_uuid': 'id'}
        # manage a typo in the api in order to have the correct name in the payload.
        config_translation = {
            'user_groups_retrieve_strategy': USER_GROUP_RETRIEVE_STRATEGY_LABEL,
            'member_of_ldap_attribute': 'memberof.ldap.attribute',
        }

        not_mapper_argument = list(keycloak_argument_spec().keys()) + [
            'state',
            'realm',
            'federation_id',
        ]

        config = {}
        payload = {
            'providerId': 'group-ldap-mapper',
            'providerType': 'org.keycloak.storage.ldap.mappers.LDAPStorageMapper',
        }
        if self.federation:
            payload.update({'parentId': self.federation.uuid})
        for key, value in self.module.params.items():
            if value is not None and key not in not_mapper_argument:
                if key in list(translation.keys()):
                    payload.update({translation[key]: value})
                elif key in list(config_translation.keys()):
                    config.update({config_translation[key]: [value]})
                elif key == 'groups_ldap_filter':
                    config.update({snake_to_point_case(key): [value.strip()]})
                elif key in ['mapped_group_attributes', 'group_object_classes']:
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
            'groups.dn': 'ab',
            'group.name.ldap.attribute': 'cn',
            'group.object.classes': 'groupOfNames',
            'preserve.group.inheritance': 'true',
            'ignore.missing.groups': 'false',
            'membership.ldap.attribute': 'member',
            'membership.attribute.type': 'DN',
            'membership.user.ldap.attribute': 'cn',
            'groups.ldap.filter': '',
            'mode': 'LDAP_ONLY',
            'user.roles.retrieve.strategy': 'LOAD_GROUPS_BY_MEMBER_ATTRIBUTE',
            'memberof.ldap.attribute': 'memberOf',
            'mapped.group.attributes': '',
            'drop.non.existing.groups.during.sync': 'false',
        }
        payload.update(
            {'config': if_absent_add_a_default_value(new_configuration, dict_of_default)}
        )
        return payload

    @staticmethod
    def _check_arguments(new_configuration):
        try:
            preserve_group_inheritance = convert_to_bool(
                new_configuration['preserve.group.inheritance'][0]
            )
            membership_attribute_type = new_configuration['membership.attribute.type'][0]
        except KeyError:
            pass
        else:
            if preserve_group_inheritance and (membership_attribute_type == 'UID'):
                raise KeycloakError(
                    'Not possible to preserve group inheritance and use UID membership type together.'
                )
        try:
            user_groups_retrieve_strategy = new_configuration[USER_GROUP_RETRIEVE_STRATEGY_LABEL][
                0
            ]
            member_of_ldap_attribute = new_configuration['memberof.ldap.attribute'][0]
        except KeyError:
            pass
        else:
            if (
                user_groups_retrieve_strategy != 'GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE'
                and member_of_ldap_attribute
            ):
                raise KeycloakError(
                    'member of ldap attribute is only useful when user groups strategy is get groups '
                    'from user member of attribute.'
                )
        try:
            ldap_filter = new_configuration[snake_to_point_case('groups_ldap_filter')][0].strip()
        except KeyError:
            pass
        else:
            if ldap_filter[0] != '(' and ldap_filter[-1] != ')':
                raise KeycloakError(
                    'LDAP filter should begin with a opening bracket and end with closing bracket.'
                )

    def create(self, check=False):
        if not self.module.params.get('groups_dn'):
            raise KeycloakError('groups_dn is mandatory for group mapper creation.')
        super(FederationGroupMapper, self).create(check)


def run_module():
    argument_spec = keycloak_argument_spec()
    meta_args = dict(
        realm=dict(type='str', default='master'),
        federation_id=dict(type='str'),
        federation_uuid=dict(type='str'),
        mapper_name=dict(type='str'),
        mapper_uuid=dict(type='str'),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        groups_dn=dict(type='str'),
        group_name_ldap_attribute=dict(type='str'),
        group_object_classes=dict(type='list'),
        preserve_group_inheritance=dict(type='bool'),
        ignore_missing_groups=dict(type='bool'),
        membership_ldap_attribute=dict(type='str'),
        membership_attribute_type=dict(type='str', choices=['DN', 'UID']),
        membership_user_ldap_attribute=dict(type='str'),
        groups_ldap_filter=dict(type='str'),  # should begin with a ( and end with another )
        mode=dict(type='str', choices=['LDAP_ONLY', 'IMPORT', 'READ_ONLY']),
        user_groups_retrieve_strategy=dict(
            type='str',
            choices=[
                'LOAD_GROUPS_BY_MEMBER_ATTRIBUTE',
                'GET_GROUPS_FROM_USER_MEMBEROF_ATTRIBUTE',
                'LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY',
            ],
        ),
        member_of_ldap_attribute=dict(type='str'),
        mapped_group_attributes=dict(type='list'),
        drop_non_existing_groups_during_sync=dict(type='bool'),
    )
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
            group_mapper={},
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
        federation_group_mapper = FederationGroupMapper(module, connection_header)
        result = crud_with_instance(federation_group_mapper, 'group_mapper')
    except KeycloakError as err:
        module.fail_json(msg=str(err), changed=False, group_mapper={})

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
