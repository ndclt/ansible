# Copyright: (c) 2018, Nicolas Duclert <nicolas.duclert@metronlab.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

from copy import deepcopy

from ansible.module_utils.common.dict_transformations import recursive_diff
from ansible.module_utils.identity.keycloak.keycloak import (
    KeycloakError,
    get_on_url,
    put_on_url,
    delete_on_url,
    post_on_url,
)
from ansible.module_utils.identity.keycloak.keycloak_ldap_federation import (
    LdapFederationBase,
    COMPONENTS_URL,
)
from ansible.module_utils.identity.keycloak.urls import COMPONENTS_BY_UUID_URL, MAPPER_BY_NAME
from ansible.module_utils.identity.keycloak.utils import clean_payload_with_config

from ansible.module_utils.six.moves.urllib.parse import quote

WAITED_PROVIDER_ID = {
    'role': 'role-ldap-mapper',
    'group': 'group-ldap-mapper',
    'user attributes': 'user-attribute-ldap-mapper',
    'full name': 'full-name-ldap-mapper',
}


class FederationMapper(object):
    def __init__(self, module, connection_header, mapper_type):
        self.module = module
        self.restheaders = connection_header
        self.uuid = self.module.params.get('mapper_uuid')
        self.description = '{mapper_type} mapper {given_id}'.format(
            given_id=self.given_id, mapper_type=mapper_type
        )
        if self.module.params.get('mapper_name'):
            self.federation = LdapFederationBase(module, connection_header)
            if not self.federation.uuid:
                raise KeycloakError(
                    'Cannot access mapper because {} federation does not exist.'.format(
                        self.federation.given_id
                    )
                )
        else:
            self.federation = None
        self.initial_representation = self.representation
        try:
            self.uuid = self.initial_representation['id']
        except KeyError:
            pass
        else:
            if self.initial_representation['providerId'] != WAITED_PROVIDER_ID[mapper_type]:
                raise KeycloakError(
                    '{given_id} is not a {mapper_type} mapper.'.format(
                        given_id=self.given_id, mapper_type=mapper_type
                    )
                )

    @property
    def given_id(self):
        """Get the asked mapper id given by the user.

        :return the asked id given by the user as a name or an uuid.
        :rtype: str
        """
        if self.module.params.get('mapper_name'):
            return self.module.params.get('mapper_name')
        return self.module.params.get('mapper_uuid')

    @property
    def representation(self):
        return clean_payload_with_config(
            get_on_url(
                url=self._get_mapper_url(),
                restheaders=self.restheaders,
                module=self.module,
                description=self.description,
            )
        )

    def _get_mapper_url(self):
        """Create the url in order to get the federation from the given argument (uuid or name)
        :return: the url as string
        :rtype: str"""
        if self.uuid:
            return COMPONENTS_BY_UUID_URL.format(
                url=self.module.params.get('auth_keycloak_url'),
                realm=quote(self.module.params.get('realm')),
                uuid=quote(self.uuid),
            )
        return MAPPER_BY_NAME.format(
            url=self.module.params.get('auth_keycloak_url'),
            realm=quote(self.module.params.get('realm')),
            mapper_name=quote(self.module.params.get('mapper_name').lower()),
            federation_uuid=self.federation.uuid,
        )

    def update(self, check=False):
        if not self._arguments_update_representation():
            return {}
        payload = self._create_payload()
        if check:
            return clean_payload_with_config(payload)
        put_on_url(
            self._get_mapper_url(), self.restheaders, self.module, self.description, payload
        )
        return clean_payload_with_config(payload)

    def _arguments_update_representation(self):
        clean_payload = clean_payload_with_config(self._create_payload(), credential_clean=False)
        payload_without_empty_values = deepcopy(clean_payload)
        for key, value in clean_payload['config'].items():
            if not isinstance(value, bool) and not value:
                payload_without_empty_values['config'].pop(key)
        payload_diff, _ = recursive_diff(payload_without_empty_values, self.initial_representation)
        try:
            config_diff = payload_diff.pop('config')
        except KeyError:
            config_diff = {}
        if not payload_diff and not config_diff:
            return False
        return True

    def _create_payload(self):
        raise NotImplemented

    def delete(self):
        delete_on_url(self._get_mapper_url(), self.restheaders, self.module, self.description)

    def create(self, check=False):
        payload = self._create_payload()
        if check:
            return clean_payload_with_config(payload)
        post_url = COMPONENTS_URL.format(
            url=self.module.params.get('auth_keycloak_url'),
            realm=quote(self.module.params.get('realm')),
        )
        post_on_url(
            url=post_url,
            restheaders=self.restheaders,
            module=self.module,
            description=self.description,
            representation=payload,
        )
        return clean_payload_with_config(payload)
