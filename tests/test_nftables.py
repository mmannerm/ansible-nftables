import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    '.molecule/ansible_inventory').get_hosts('all')


def test_nftables_is_running(Service):
    s = Service('nftables')
    assert s.is_running
    assert s.is_enabled
