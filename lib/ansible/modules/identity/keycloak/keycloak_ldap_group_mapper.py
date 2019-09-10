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
'''

EXAMPLES = r'''
'''

RETURN = r'''
'''

from ansible.module_utils.identity.keycloak.keycloak import (
    keycloak_argument_spec,
    get_token,
    post_on_url,
    KeycloakError,
)