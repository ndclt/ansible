from ansible.modules.identity.keycloak import keycloak_user
from units.modules.utils import AnsibleExitJson, AnsibleFailJson, fail_json, exit_json, set_module_args


# def get_bin_path(arg, required=False):
#     """Mock AnsibleModule.get_bin_path"""
#     if arg.endswith('my_command'):
#         return '/usr/bin/my_command'
#     else:
#         if required:
#             fail_json(msg='%r not found !' % arg)


def test_nothing_to_do(monkeypatch, capsys):
    monkeypatch.setattr(keycloak_user.AnsibleModule, 'exit_json', fail_json)
    set_module_args(
        {
            'auth_keycloak_url': 'http://keycloak.url',
            'auth_username': 'nd',
            'auth_password': 'nd',
            'auth_realm': 'master',
            'keycloak_username': 'blu',
            'state': 'absent'
        })
    keycloak_user.main()
    assert True
