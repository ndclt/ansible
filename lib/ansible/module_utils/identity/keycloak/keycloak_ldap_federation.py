# Copyright: (c) 2018, Nicolas Duclert <nicolas.duclert@metronlab.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils.identity.keycloak.utils import clean_payload_with_config
from ansible.module_utils.identity.keycloak.keycloak import get_on_url
from ansible.module_utils.six.moves.urllib.parse import quote

USER_FEDERATION_URL = '{url}/admin/realms/{realm}/components?parent={realm}&type=org.keycloak.storage.UserStorageProvider&name={federation_id}'
USER_FEDERATION_BY_UUID_URL = '{url}/admin/realms/{realm}/components/{uuid}'
COMPONENTS_URL = '{url}/admin/realms/{realm}/components/'


class LdapFederationBase(object):
    def __init__(self, module, connection_header):
        self.module = module
        self.restheaders = connection_header
        self.uuid = self.module.params.get('federation_uuid')
        self.initial_representation = clean_payload_with_config(
            self.get_federation(), credential_clean=False
        )
        self.description = 'federation {given_id}'.format(given_id=self.given_id)
        try:
            self.uuid = self.initial_representation['id']
        except KeyError:
            pass

    def _get_federation_url(self):
        """Create the url in order to get the federation from the given argument (uuid or name)
        :return: the url as string
        :rtype: str
        """
        if self.uuid:
            return USER_FEDERATION_BY_UUID_URL.format(
                url=self.module.params.get('auth_keycloak_url'),
                realm=quote(self.module.params.get('realm')),
                uuid=quote(self.uuid),
            )
        return USER_FEDERATION_URL.format(
            url=self.module.params.get('auth_keycloak_url'),
            realm=quote(self.module.params.get('realm')),
            federation_id=quote(self.module.params.get('federation_id')),
        )

    def get_federation(self):
        """Get the federation information from keycloak

        :return: the federation representation as a dictionary, if the asked
        representation does not exist, a empty dictionary is returned.
        :rtype: dict
        """
        json_federation = get_on_url(
            url=self._get_federation_url(),
            restheaders=self.restheaders,
            module=self.module,
            description='user federation {}'.format(self.given_id)
        )
        if json_federation:
            try:
                return json_federation[0]
            except KeyError:
                return json_federation
        return {}

    @property
    def given_id(self):
        """Get the asked id given by the user.

        :return the asked id given by the user as a name or an uuid.
        :rtype: str
        """
        if self.module.params.get('federation_id'):
            return self.module.params.get('federation_id')
        return self.module.params.get('federation_uuid')
