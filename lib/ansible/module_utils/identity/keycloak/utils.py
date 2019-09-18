# Copyright: (c) 2018, Nicolas Duclert <nicolas.duclert@metronlab.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

from copy import deepcopy


def if_absent_add_a_default_value(payload, dict_of_default, config=True):
    for key in dict_of_default:
        try:
            payload[key]
        except KeyError:
            if dict_of_default[key] is None:
                if config:
                    payload.update({key: []})
                else:
                    payload.update({key: ''})
            else:
                if config:
                    payload.update({key: [dict_of_default[key]]})
                else:
                    payload.update({key: dict_of_default[key]})
    return payload


def snake_to_point_case(word):
    return word.replace('_', '.')


def convert_to_bool(bool_argument):
    if isinstance(bool_argument, bool):
        return bool_argument
    if isinstance(bool_argument, str):
        if bool_argument.lower() == 'false':
            return False
        if bool_argument.lower() == 'true':
            return True
    return bool(bool_argument)


def clean_payload_with_config(payload, credential_clean=True):
    """Clean the payload from credentials and extra list.

    :param payload: the payload given to the post or put request.
    :return: the cleaned payload
    :rtype: dict
    """
    if not payload:
        return {}
    clean_payload = deepcopy(payload)
    try:
        old_config = clean_payload.pop('config')
    except TypeError:
        clean_payload = clean_payload[0]
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
