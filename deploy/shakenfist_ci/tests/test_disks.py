from shakenfist_ci import base


class TestDisks(base.BaseNamespacedTestCase):
    """Make sure instances boot under various configurations."""

    def __init__(self, *args, **kwargs):
        kwargs['namespace_prefix'] = 'disks'
        super(TestDisks, self).__init__(*args, **kwargs)

    def setUp(self):
        super(TestDisks, self).setUp()
        self.net = self.test_client.allocate_network(
            '192.168.242.0/24', True, True, self.namespace)
        self._await_networks_ready([self.net['uuid']])

    def test_boot_nvme(self):
        inst = self.test_client.create_instance(
            'test-cirros-boot-nvme', 1, 1024,
            [
                {
                    'network_uuid': self.net['uuid']
                }
            ],
            [
                {
                    'size': 8,
                    'base': 'ubuntu:20.04',
                    'type': 'disk',
                    'bus': 'nvme'
                }
            ], None, base.load_userdata('bootok'))

        self.assertInstanceConsoleAfterBoot(inst['uuid'], 'System booted ok')

        self.test_client.delete_instance(inst['uuid'])
        inst_uuids = []
        for i in self.test_client.get_instances():
            inst_uuids.append(i['uuid'])
        self.assertNotIn(inst['uuid'], inst_uuids)
