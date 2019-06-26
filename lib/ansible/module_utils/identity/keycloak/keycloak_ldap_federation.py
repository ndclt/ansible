# Copyright: (c) 2018, Nicolas Duclert <nicolas.duclert@metronlab.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from copy import deepcopy

from ansible.module_utils.identity.keycloak.keycloak import get_on_url
from ansible.module_utils.six.moves.urllib.parse import quote

USER_FEDERATION_URL = '{url}/admin/realms/{realm}/components?parent={realm}&type=org.keycloak.storage.UserStorageProvider&name={federation_id}'
USER_FEDERATION_BY_UUID_URL = '{url}/admin/realms/{realm}/components/{uuid}'


class LdapFederationBase(object):
    def __init__(self, module, connection_header):
        self.module = module
        self.restheaders = connection_header
        self.federation = self._clean_payload(
            self.get_federation(), credential_clean=False
        )
        try:
            self.uuid = self.federation['id']
        except KeyError:
            self.uuid = ''

    def _get_federation_url(self):
        """Create the url in order to get the federation from the given argument (uuid or name)
        :return: the url as string
        :rtype: str
        """
        try:
            return USER_FEDERATION_BY_UUID_URL.format(
                url=self.module.params.get('auth_keycloak_url'),
                realm=quote(self.module.params.get('realm')),
                uuid=self.uuid,
            )
        except AttributeError:
            if self.module.params.get('federation_id'):
                return USER_FEDERATION_URL.format(
                    url=self.module.params.get('auth_keycloak_url'),
                    realm=quote(self.module.params.get('realm')),
                    federation_id=quote(self.module.params.get('federation_id')),
                )
            return USER_FEDERATION_BY_UUID_URL.format(
                url=self.module.params.get('auth_keycloak_url'),
                realm=quote(self.module.params.get('realm')),
                uuid=quote(self.module.params.get('federation_uuid')),
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

    @staticmethod
    def _clean_payload(payload, credential_clean=True):
        """Clean the payload from credentials and extra list.

        :param payload: the payload given to the post or put request.
        :return: the cleaned payload
        :rtype: dict
        """
        if not payload:
            return {}
        clean_payload = deepcopy(payload)
        old_config = clean_payload.pop('config')
        new_config = {}
        for key, value in old_config.items():
            if key == 'bindCredential' and credential_clean:
                new_config.update({key: 'no_log'})
            else:
                try:
                    new_config.update({key: value[0]})
                except IndexError:
                    new_config.update({key: None})

        clean_payload.update({'config': new_config})
        return clean_payload

    @property
    def given_id(self):
        """Get the asked id given by the user.

        :return the asked id given by the user as a name or an uuid.
        :rtype: str
        """
        if self.module.params.get('federation_id'):
            return self.module.params.get('federation_id')
        return self.module.params.get('federation_uuid')
