#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Nicolas Duclert <nicolas.duclert@metronlab.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community',
}

DOCUMENTATION = r'''
---
module: keycloak_ldap_synchronization

short_description: Allows synchronization operations of Keycloak with a LDAP server via Keycloak API

description:
  - This module allows you to synchronized users with an LDAP server describe 
    in the LDAP federation. The authorized operations are changed user or full
    synchronization, remove the imported users or unlink the imported users
    from the LDAP.
    
  - The names of module options are snake_cased versions of the camelCase ones found in the
    Keycloak API and its documentation at U(http://www.keycloak.org/docs-api/4.8/rest-api/).
    
version_added: "2.10"

options:
  realm:
    type: str
    description:
      - They Keycloak realm under which the LDAP federation to synchronize resides.
    default: 'master'

  federation_id:
    description:
      - The name of the federation to synchronize
      - Also called ID of the federation in the table of federations or
        the console display name in the detailed view of a federation
      - This parameter is mutually exclusive with I(federation_uuid) and one
        of them is required by the module
    type: str
    aliases: [ federerationId ]

  federation_uuid:
    description:
      - The uuid of the federation to synchronize
      - This parameter is mutually exclusive with I(federation_id) and one
        of them is required by the module
    type: str
    aliases: [ federationUuid ]

  synchronize_changed_users:
    description:
      - Whether to synchronized only changed users
      - This parameter is mutually exclusive with I(synchronize_all_users),
        I(remove_imported), I(unlink_users) and one of them is required by the
        module.
    type: bool
    aliases: [ sync_changed_users, syncChangedUsers, synchronizeChangedUsers ]

  synchronize_all_users:
    description:
      - Whether to synchronized all users (delete extra users on the Keycloak,
        import new users from the LDAP).
      - This parameter is mutually exclusive with I(synchronize_changed_users),
        I(remove_imported), I(unlink_users) and one of them is required by the
        module.
    type: bool
    aliases: [ sync_all_users, synchronizeAllUsers, syncAllUsers ]

  remove_imported:
    description:
      - Whether to delete users imported from the Keycloak.
      - This parameter is mutually exclusive with I(synchronize_changed_users),
        I(synchronize_all_users), I(unlink_users) and one of them is required
        by the module.
    type: bool
    aliases: [ removeImported ]

  unlink_users:
    description:
      - Whether to cut the link between the imported users and the Keycloak,
        this will prevent an update from the LDAP.
      - This parameter is mutually exclusive with I(synchronize_changed_users),
        I(synchronize_all_users), I(remove_imported) and one of them is required
        by the module.
    type: bool
    aliases: [ unlinkUsers ]

extends_documentation_fragment:
  - keycloak

author:
  - Nicolas Duclert (@ndclt)
'''

EXAMPLES = r'''
- name: Synchronize all the users from the LDAP
  keycloak_ldap_synchronization:
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    realm: master
    federation_id: my-company-ldap
    synchronize_all_users: True
'''

RETURN = r'''
msg:
  description: Message as to what action was taken
  returned: always
  type: str
  sample: "2 imported users, 2 updated users, 1 removed."

changed:
  description: whether the state of the keycloak configuration change
  returned: always
  type: bool
'''

import json
from json import JSONDecodeError

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule

from ansible.module_utils.identity.keycloak.keycloak_ldap_federation import (
    LdapFederationBase,
)
from ansible.module_utils.identity.keycloak.keycloak import (
    keycloak_argument_spec,
    get_token,
    post_on_url,
    KeycloakError,
)

ALL_OPERATIONS = ['synchronize_changed_users', 'synchronize_all_users', 'remove_imported', 'unlink_users']


class LdapSynchronization(LdapFederationBase):
    """This class manage the LDAP federation synchronization.
    """
    def __init__(self, module, connection_header):
        super(LdapSynchronization, self).__init__(module, connection_header)
        self.message = ''
        self.changed = True
        if not self.uuid:
            self.module.fail_json(
                msg=to_text(
                    'Cannot synchronize {} federation because it does not exist.'.format(
                        self.given_id
                    )
                )
            )

    def synchronize(self):
        """Do the asked synchronisation operation.
        """
        synchronize_url = self._build_url()
        response = post_on_url(synchronize_url, self.restheaders, self.module, '{} for {}'.format(self.operation, self.given_id))
        try:
            synchronisation_result = json.load(response)
        except JSONDecodeError:
            # This happens because the delete and unlink don't return a content.
            synchronisation_result = {}
        self._create_message(synchronisation_result)
        self._udpate_changed(synchronisation_result)

    def _build_url(self):
        url_dict = {
            ALL_OPERATIONS[0]: '{base_url}/admin/realms/{realm}/user-storage/{federation_uuid}/sync?action=triggerChangedUsersSync',
            ALL_OPERATIONS[1]: '{base_url}/admin/realms/{realm}/user-storage/{federation_uuid}/sync?action=triggerFullSync',
            ALL_OPERATIONS[2]: '{base_url}/admin/realms/{realm}/user-storage/{federation_uuid}/remove-imported-users',
            ALL_OPERATIONS[3]: '{base_url}/admin/realms/{realm}/user-storage/{federation_uuid}/unlink-users',
        }
        return url_dict[self.operation].format(
            base_url=self.module.params.get('auth_keycloak_url'),
            realm=self.module.params.get('realm'),
            federation_uuid=self.uuid,
        )

    @property
    def operation(self):
        """Get the operation name given as module parameter.

        :return: the user given operation name.
        """
        for one_name in ALL_OPERATIONS:
            potential_operation = self.module.params.get(one_name)
            if potential_operation:
                return one_name

    def _create_message(self, synchronisation_result):
        """Create the message for the result or fail json."""
        # only the synchronization return a dictionary
        if synchronisation_result:
            self.message = synchronisation_result['status'] + '.'
        else:
            if self.operation == ALL_OPERATIONS[2]:
                self.message = 'Remove imported users from {}.'.format(self.given_id)
            elif self.operation == ALL_OPERATIONS[3]:
                self.message = 'Unlink users of {}.'.format(self.given_id)
            else:
                raise ValueError('The operation does not have a message.')

    def _udpate_changed(self, synchronisation_result):
        """With the returned informations, try to know if the keycloak is changed."""
        # if the post does not return a response, it is a call to unlink or
        # remove. The changed status have to stay to True..
        if synchronisation_result:
            no_user_is_changed = (
                    synchronisation_result['added'] == 0
                    and synchronisation_result['updated'] == 0
                    and synchronisation_result['removed'] == 0
            )
            if synchronisation_result['ignored'] or no_user_is_changed:
                self.changed = False


def run_module():
    argument_spec = keycloak_argument_spec()
    meta_args = dict(
        realm=dict(type='str', default='master'),
        federation_id=dict(type='str', aliases=['federerationId']),
        federation_uuid=dict(type='str', aliases=['federationUuid']),
        synchronize_changed_users=dict(type='bool', aliases=['sync_changed_users', 'syncChangedUsers', 'synchronizeChangedUsers']),
        synchronize_all_users=dict(type='bool', aliases=['sync_all_users', 'synchronizeAllUsers', 'syncAllUsers']),
        remove_imported=dict(type='bool', aliases=['removeImported']),
        unlink_users=dict(type='bool', aliases=['unlinkUsers']),
    )
    argument_spec.update(meta_args)

    # The id of the role is unique in keycloak and if it is given the
    # client_id is not used. In order to avoid confusion, I set a mutual
    # exclusion.
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_one_of=[
            ['federation_id', 'federation_uuid'],
            ALL_OPERATIONS,
        ],
        mutually_exclusive=[
            ['federation_id', 'federation_uuid'],
            ALL_OPERATIONS,
        ],
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
    except KeycloakError as err:
        module.fail_json(msg=err)
    ldap_synchronization = LdapSynchronization(module, connection_header)
    ldap_synchronization.synchronize()
    result = {
        'changed': ldap_synchronization.changed,
        'msg': to_text(ldap_synchronization.message),
    }
    if 'failed' in ldap_synchronization.message:
        module.fail_json(**result)
    else:
        module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
