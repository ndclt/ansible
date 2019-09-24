#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Nicolas Duclert <nicolas.duclert@metronlab.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1', 'status': ['preview'], 'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: keycloak_ldap_full_name_mapper

short_description: Allows administration of Keycloak LDAP full name mapper via Keycloak API
description:
  - This module allows you to add, remove or modify Keycloak LDAP full name mapper via the Keycloak API.
    It requires access to the REST API via OpenID Connect; the user connecting and the client being
    used must have the requisite access rights. In a default Keycloak installation, admin-cli
    and an admin user would work, as would a separate client definition with the scope tailored
    to your needs and a user having the expected roles.

  - When updating a LDAP full name mapper federation, where possible provide the mapper ID to the
    module. This removes a lookup to the API to translate the name into the mapper ID.

  - This module has been tested against keycloak 6.0, the backward compatibility is not guaranteed. 

version_added: "2.10"
options:
  state:
    description:
      - State of the LDAP federation mapper.
      - On C(present), the full name mapper will be created if it does not yet exist, or updated 
        with the parameters you provide.
      - On C(absent), the full name mapper will be removed if it exists.
    required: true
    default: present
    type: str
    choices:
      - present
      - absent

  realm:
    type: str
    description:
      - They Keycloak realm under which this LDAP full name mapper resides.
    default: 'master'

  federation_id:
    description:
      - The name of the federation
      - Also called ID of the federation in the table of federations or
        the console display name in the detailed view of a federation
      - This parameter is mutually exclusive with I(federation_uuid) and one
        of them is required by the module if I(mapper_name) is given
    type: str

  federation_uuid:
    description:
      - The uuid of the federation
      - This parameter is mutually exclusive with I(federation_id) and one
        of them is required by the module if I(mapper_name) is given
    type: str
  
  mapper_name:
    description:
      - The name of the full name mapper
      - This parameter is mutually exclusive with I(mapper_uuid) and one
        of them is required by the module
    type: str
        
  mapper_uuid:
    description:
      - The uuid of the full name mapper
      - This parameter is mutually exclusive with I(mapper_name) and one
        of them is required by the module
    type: str
  
  ldap_full_name_attribute:
    description:
      - Name of LDAP attribute, which contains fullName of user
    type: str
  
  read_only:
    description:
      - if C(True) data imported from LDAP to Keycloak DB, but it's not saved back to LDAP when 
        user is updated in Keycloak
    type: bool
  
  write_only:
    description:
      - if C(True) data propagated to LDAP when user is created or updated in Keycloak. But this 
        mapper is not used to propagate data from LDAP back into Keycloak. This setting is useful 
        if you configured separate firstName and lastName attribute mappers and you want to use 
        those to read attribute from LDAP into Keycloak
    type: bool
'''

EXAMPLES = r'''
- name: Minimal creation
  keycloak_full_name_ldap_mapper:
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    state: present
    federation_id: my-company-ldap
    mapper_name: full-name-mapper-for-company
    ldap_full_name_attribute: dn
- name: Creation or update with all arguments
  keycloak_full_name_ldap_mapper:
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    state: present
    federation_id: my-company-ldap
    mapper_name: full-name-mapper-for-company
    ldap_full_name_attribute: cn
    read_only: yes
    write_only: no
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

full_name_ldap_mapper:
  description: the LDAP full name mapper representation. Empty if the asked full name mapper is deleted or does not exist.
  returned: always
  type: dict
  contains:
    name:
      description: name of the LDAP role mapper
      type: str
      returned: on success
      sample: group-ldap-mapper1
    providerId:
      description: the id of the full name mapper, always C(full-name-ldap-mapper) for this module
      type: str
      returned: on success
      sample: role-ldap-mapper
    parentId:
      description: the LDAP full name mapper parent uuid
      type: str
      returned: on success
      sample: de455375-6900-46a0-8d11-51554e1c3f18
    providerType:
      description: the type of the object, for this module always C(org.keycloak.storage.ldap.mappers.LDAPStorageMapper)
      type: str
      returned: on success
      sample: org.keycloak.storage.ldap.mappers.LDAPStorageMapper
    config:
      description: the configuration of the LDAP full name mapper
      type: dict
      returned: on success
      contains:
        ldap.full.name.attribute:
          description: Name of LDAP attribute, which contains fullName of user
          type: str
          returned: on success
        read.only:
          description: show if data is imported from LDAP to Keycloak DB
          type: bool
          returned: on success
        write.only:
          description: show if data propagated to LDAP when user is created or updated in Keycloak
          type: bool
          returned: on success
'''

from ansible.module_utils.common.dict_transformations import dict_merge
from ansible.module_utils.identity.keycloak.crud import crud_with_instance
from ansible.module_utils.identity.keycloak.utils import (
    snake_to_point_case,
    if_absent_add_a_default_value,
)
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.identity.keycloak.keycloak import (
    keycloak_argument_spec,
    get_token,
    KeycloakError,
)
from ansible.module_utils.identity.keycloak.keycloak_ldap_mapper import FederationMapper


class FullNameLdapMapper(FederationMapper):
    def __init__(self, module, connection_header):
        super(FullNameLdapMapper, self).__init__(
            module=module, connection_header=connection_header, mapper_type='full name'
        )

    def _create_payload(self):
        translation = {'mapper_name': 'name', 'mapper_uuid': 'id'}
        config = {}
        payload = {
            'providerId': 'full-name-ldap-mapper',
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
                elif isinstance(value, bool):
                    config.update({snake_to_point_case(key): [str(value).lower()]})
                else:
                    config.update({snake_to_point_case(key): [value]})
        try:
            old_configuration = {
                key: [value] for key, value in self.initial_representation['config'].items()
            }
        except KeyError:
            old_configuration = {}
        new_configuration = dict_merge(old_configuration, config)
        dict_of_default = {'read.only': 'false', 'write.only': 'true'}
        payload.update(
            {'config': if_absent_add_a_default_value(new_configuration, dict_of_default)}
        )
        self._check_arguments(new_configuration)
        return payload

    @staticmethod
    def _check_arguments(new_configuration):
        try:
            read_only = new_configuration[snake_to_point_case('read_only')][0]
            write_only = new_configuration[snake_to_point_case('write_only')][0]
        except KeyError:
            pass
        else:
            if read_only.lower() == 'true' and write_only.lower() == 'true':
                raise KeycloakError('Cannot have read only and write only together')

    def create(self, check=False):
        if not self.module.params.get('ldap_full_name_attribute'):
            raise KeycloakError('ldap_full_name_attribute is mandatory for full name mapper creation.')
        super(FullNameLdapMapper, self).create(check)


def run_module():
    meta_args = dict(
        realm=dict(type='str', default='master'),
        federation_id=dict(type='str'),
        federation_uuid=dict(type='str'),
        mapper_name=dict(type='str'),
        mapper_uuid=dict(type='str'),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        ldap_full_name_attribute=dict(type='str'),
        read_only=dict(type='bool'),
        write_only=dict(type='bool'),
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
            full_name_ldap_mapper={},
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
        role_mapper = FullNameLdapMapper(module, connection_header)
        result = crud_with_instance(role_mapper, 'full_name_ldap_mapper')
    except KeycloakError as err:
        module.fail_json(msg=str(err), changed=False, full_name_ldap_mapper={})

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
