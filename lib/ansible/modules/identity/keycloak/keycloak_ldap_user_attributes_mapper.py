#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Nicolas Duclert <nicolas.duclert@metronlab.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

from ansible.module_utils.common.dict_transformations import dict_merge
from ansible.module_utils.identity.keycloak.crud import crud_with_instance
from ansible.module_utils.identity.keycloak.utils import (
    snake_to_point_case,
    if_absent_add_a_default_value,
)

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1', 'status': ['preview'], 'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: keycloak_ldap_user_attributes_mapper

short_description: Allows administration of Keycloak LDAP user attribute mapper via Keycloak API
description:
  - This module allows you to add, remove or modify Keycloak LDAP user attribute mapper via the Keycloak API.
    It requires access to the REST API via OpenID Connect; the user connecting and the client being
    used must have the requisite access rights. In a default Keycloak installation, admin-cli
    and an admin user would work, as would a separate client definition with the scope tailored
    to your needs and a user having the expected roles.

  - When updating a LDAP user attribute mapper federation, where possible provide the mapper ID to the
    module. This removes a lookup to the API to translate the name into the mapper ID.

  - This module has been tested against keycloak 6.0, the backward compatibility is not garanteed. 

version_added: "2.10"
options:
  state:
    description:
      - State of the LDAP federation mapper.
      - On C(present), the user attribute mapper will be created if it does not yet exist, or 
        updated with the parameters you provide.
      - On C(absent), the user attribute mapper will be removed if it exists.
    required: true
    default: present
    type: str
    choices:
      - present
      - absent

  realm:
    type: str
    description:
      - They Keycloak realm under which this LDAP user attribute mapper resides.
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
      - The name of the user attribute mapper
      - This parameter is mutually exclusive with mapper_uuid and one
        of them is required by the module
    type: str
        
  mapper_uuid:
    description:
      - The uuid of the user attribute mapper
      - This parameter is mutually exclusive with mapper_name and one
        of them is required by the module
    type: str

  user_model_attribute:
    description:
      - Name of the UserModel property or attribute you want to map the LDAP attribute into
      - Mandatory when creating the mapper
    type: str
  
  ldap_attribute:
    description:
      - Name of mapped attribute on LDAP object
      - Mandatory when creating the mapper
    type: str
  
  is_mandatory_in_ldap:
    description:
      - if C(True), attribute is mandatory in LDAP. Hence if there is no value in Keycloak DB, the 
        empty value will be set to be propagated to LDAP
    type: bool
  
  read_only:
    description:
      - if C(True), attribute is imported from LDAP to UserModel, but it's not saved back to LDAP 
        when user is updated in Keycloak.
    type: bool
  
  always_read_value_from_ldap:
    description:
      - If C(True), then during reading of the LDAP attribute value will always used instead of
        the value from Keycloak DB
    type: bool
  
  is_binary_attribute:
    description:
      - Should be C(True) for binary LDAP attributes
      - If set to C(True), then I(always_read_value_from_ldap) must be set to C(True).
    type: bool
'''

EXAMPLES = r'''
- name: Role exists, update it
  keycloak_ldap_user_attributes_mapper:
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    realm: master
    state: present
    federation_id: my-company-ldap
    mapper_name: user-attribute-mapper-for-company
    is_mandatory_in_ldap: yes
    read_only: yes
    always_read_value_from_ldap: yes
    is_binary_attribute: no
'''

RETURN = r'''
msg:
  description: Message as to what action was taken
  returned: always
  type: str
  sample: "User attributes mapper my-group-mapper created."

changed:
  description: whether the state of the keycloak configuration change
  returned: always
  type: bool

user_attribute_mapper:
  description: the LDAP user attributes mapper representation. Empty if the asked user attributes mapper is deleted or does not exist.
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
        user.model.attribute:
          description: Name of the UserModel property or attribute you want to map the LDAP attribute into
          returned: on success
          sample: firstName
        ldap.attribute:
          description: Name of mapped attribute on LDAP object
          returned: on success
          sample: cn
        read.only:
          description: Read-only attribute is imported from LDAP to UserModel
          returned: on success
          sample: true
        always.read.value.from.ldap:
          description: If on, then during reading of the LDAP attribute value will always used instead of the value from Keycloak DB
          returned: on success
          sample: true
        is.mandatory.in.ldap:
          description: If true, attribute is mandatory in LDAP. Hence if there is no value in Keycloak DB, the empty value will be set to be propagated to LDAP
          returned: on success
          sample: true
        is.binary.attribute:
          description: Should be true for binary LDAP attributes
          returned: on success
          sample: true
'''

from ansible.module_utils.identity.keycloak.keycloak_ldap_mapper import FederationMapper

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.identity.keycloak.keycloak import (
    keycloak_argument_spec,
    get_token,
    KeycloakError,
)


class FederationUserAttributesMapper(FederationMapper):
    def __init__(self, module, connection_header):
        super(FederationUserAttributesMapper, self).__init__(
            module=module, connection_header=connection_header, mapper_type='user attributes'
        )

    def _create_payload(self):
        translation = {'mapper_name': 'name', 'mapper_uuid': 'id'}
        config = {}
        payload = {
            'providerId': 'user-attribute-ldap-mapper',
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
        self._check_arguments(new_configuration)
        dict_of_default = {
            'is.mandatory.in.ldap': 'false',
            'is.binary.attribute': 'false',
            'always.read.value.from.ldap': 'false',
            'read.only': 'false',
        }
        payload.update(
            {'config': if_absent_add_a_default_value(new_configuration, dict_of_default)}
        )
        return payload

    @staticmethod
    def _check_arguments(new_configuration):
        try:
            binary_attribute = new_configuration[snake_to_point_case('is_binary_attribute')][0]
            always_read = new_configuration[snake_to_point_case('always_read_value_from_ldap')][0]
        except KeyError:
            pass
        else:
            if binary_attribute == 'true' and always_read == 'false':
                raise KeycloakError(
                    'With is_binary_attribute to yes, the always_read_value_from_ldap must be to yes too'
                )

    def create(self, check=False):
        ldap_attribute = self.module.params.get('ldap_attribute')
        user_model_attribute = self.module.params.get('user_model_attribute')
        if not ldap_attribute or not user_model_attribute:
            raise KeycloakError(
                'ldap_attribute and user_model_attribute are mandatory for creating a user '
                'attributes mapper.'
            )
        super(FederationUserAttributesMapper, self).create(check)


def run_module():
    meta_args = dict(
        realm=dict(type='str', default='master'),
        federation_id=dict(type='str'),
        federation_uuid=dict(type='str'),
        mapper_name=dict(type='str'),
        mapper_uuid=dict(type='str'),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        user_model_attribute=dict(type='str'),
        ldap_attribute=dict(type='str'),
        is_mandatory_in_ldap=dict(type='bool'),
        read_only=dict(type='bool'),
        always_read_value_from_ldap=dict(type='bool'),
        is_binary_attribute=dict(type='bool'),
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
            user_attribute_mapper={},
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
        role_mapper = FederationUserAttributesMapper(module, connection_header)
        result = crud_with_instance(role_mapper, 'user_attribute_mapper')
    except KeycloakError as err:
        module.fail_json(msg=str(err), changed=False, user_attribute_mapper={})

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
