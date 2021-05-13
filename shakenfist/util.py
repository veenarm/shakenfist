# Copyright 2020 Michael Still

import importlib
import json
import multiprocessing
import os
from pbr.version import VersionInfo
import random
import re
import requests
import secrets
import string
import sys
import time
import traceback

from oslo_concurrency import processutils

from shakenfist import db
from shakenfist.config import config
from shakenfist import exceptions
from shakenfist import logutil


LOG, _ = logutil.setup(__name__)


class RecordedOperation():
    def __init__(self, operation, relatedobject):
        self.operation = operation
        self.object = relatedobject

    def __enter__(self):
        self.start_time = time.time()
        object_type, object_uuid = self.unique_label()
        if object_type and object_uuid:
            db.add_event(object_type, object_uuid,
                         self.operation, 'start', None, None)
        return self

    def __exit__(self, *args):
        duration = time.time() - self.start_time
        log = LOG
        object_type, object_uuid = self.unique_label()
        if object_uuid:
            if object_type:
                db.add_event(object_type, object_uuid,
                             self.operation, 'finish', duration, None)
                log = LOG.with_object(self.object)
            else:
                log = LOG.with_field({'label', self.object})
        log.with_field('duration', duration).info('Finish %s', self.operation)

    def unique_label(self):
        if self.object:
            if isinstance(self.object, str):
                object_type = None
                object_uuid = self.object
            else:
                object_type, object_uuid = self.object.unique_label()
        else:
            object_type = None
            object_uuid = None

        return object_type, object_uuid


def is_network_node():
    """Test if this node is the network node."""
    return config.NODE_IP == config.NETWORK_NODE_IP


def _clean_ip_json(data):
    # For reasons I can't explain, the ip command sometimes returns
    # slightly bogus JSON like this:
    #
    # $ ip -pretty -json addr show enp5s0
    # [ {},{},{},{
    #         "ifindex": 2,
    #         "ifname": "enp5s0",
    #         "flags": [ "BROADCAST","MULTICAST","UP","LOWER_UP" ],
    #         "mtu": 9000,
    #         "qdisc": "pfifo_fast",
    #         "operstate": "UP",
    #         "group": "default",
    #         "txqlen": 1000,
    #         "link_type": "ether",
    #         "address": "18:c0:4d:75:50:b9",
    #         "broadcast": "ff:ff:ff:ff:ff:ff",
    #         "addr_info": [ {
    #                 "family": "inet",
    #                 "local": "192.168.1.52",
    #                 "prefixlen": 24,
    #                 "broadcast": "192.168.1.255",
    #                 "scope": "global",
    #                 "dynamic": true,
    #                 "label": "enp5s0",
    #                 "valid_life_time": 3449,
    #                 "preferred_life_time": 3449
    #             } ]
    #     },{},{},{},{},...,{} ]
    #
    # This method strips out all those empty entries in the list

    if not data:
        return []

    j = json.loads(data)
    return [x for x in j if x]


def check_for_interface(name, namespace=None, up=False):
    in_netns = ''
    if namespace:
        if not os.path.exists('/var/run/netns/%s' % namespace):
            return False

        in_netns = 'ip netns exec %s ' % namespace

    stdout, stderr = execute(
        None, '%sip -pretty -json link show %s' % (in_netns, name),
        check_exit_code=[0, 1])

    if stderr.rstrip('\n').endswith(' does not exist.'):
        return False

    if up:
        j = _clean_ip_json(stdout)
        return 'UP' in j[0]['flags']

    return True


def get_interface_addresses(name, namespace=None):
    in_namespace = ''
    if namespace:
        in_namespace = 'ip netns exec %s ' % namespace

    stdout, _ = execute(None,
                        '%(in_namespace)sip -pretty -json addr show %(name)s'
                        % {
                            'in_namespace': in_namespace,
                            'name': name
                        },
                        check_exit_code=[0, 1])

    for elem in _clean_ip_json(stdout):
        if 'addr_info' in elem:
            yield elem['addr_info']['local']


def get_interface_statistics(name, namespace=None):
    in_namespace = ''
    if namespace:
        in_namespace = 'ip netns exec %s ' % namespace

    stdout, _ = execute(None,
                        '%(in_namespace)sip -s -pretty -json link show %(name)s'
                        % {
                            'in_namespace': in_namespace,
                            'name': name
                        },
                        check_exit_code=[0, 1])

    if not stdout:
        raise exceptions.NoInterfaceStatistics(
            'No statistics for interface %s in namespace %s' % (name, namespace))

    stats = _clean_ip_json(stdout)
    return stats.get('stats64')


def get_default_routes(namespace):
    in_namespace = ''
    if namespace:
        in_namespace = 'ip netns exec %s ' % namespace

    stdout, _ = execute(None,
                        '%(in_namespace)sip route list default'
                        % {
                            'in_namespace': in_namespace
                        })
    if not stdout:
        return []

    routes = []
    for line in stdout.split('\n'):
        elems = line.split(' ')
        if len(elems) > 3 and elems[2] not in routes:
            routes.append(elems[2])
    return routes


def get_safe_interface_name(interface):
    if len(interface) > 15:
        orig_interface = interface
        interface = interface[:15]
        LOG.info('Interface name truncated from %s to %s',
                 orig_interface, interface)
    return interface


def create_interface(interface, interface_type, extra):
    interface = get_safe_interface_name(interface)
    execute(None,
            'ip link add %(interface)s type %(interface_type)s %(extra)s'
            % {'interface': interface,
               'interface_type': interface_type,
               'extra': extra})


def nat_rules_for_ipblock(ipblock):
    out, _ = execute(None, 'iptables -t nat -L POSTROUTING -n -v')
    # Output looks like this:
    # Chain POSTROUTING (policy ACCEPT 199 packets, 18189 bytes)
    # pkts bytes target     prot opt in     out     source               destination
    #   23  1736 MASQUERADE  all  --  *      ens4    192.168.242.0/24     0.0.0.0/0

    for line in out.split('\n'):
        if line.find(str(ipblock)) != -1:
            return True

    return False


LIBVIRT = None


def get_libvirt():
    global LIBVIRT

    if not LIBVIRT:
        LIBVIRT = importlib.import_module('libvirt')

    return LIBVIRT


def extract_power_state(libvirt, domain):
    state, _ = domain.state()
    if state == libvirt.VIR_DOMAIN_SHUTOFF:
        return 'off'

    if state == libvirt.VIR_DOMAIN_CRASHED:
        return 'crashed'

    if state in [libvirt.VIR_DOMAIN_PAUSED,
                 libvirt.VIR_DOMAIN_PMSUSPENDED]:
        return 'paused'

    # Covers all "running states": BLOCKED, NOSTATE,
    # RUNNING, SHUTDOWN
    return 'on'


def get_api_token(base_url, namespace='system'):
    with db.get_lock('namespace', None, namespace,
                     op='Get API token'):
        auth_url = base_url + '/auth'
        LOG.info('Fetching %s auth token from %s', namespace, auth_url)
        ns = db.get_namespace(namespace)
        if 'service_key' in ns:
            key = ns['service_key']
        else:
            key = ''.join(secrets.choice(string.ascii_lowercase)
                          for i in range(50))
            ns['service_key'] = key
            db.persist_namespace(namespace, ns)

    r = requests.request('POST', auth_url,
                         data=json.dumps({
                             'namespace': namespace,
                             'key': key
                         }),
                         headers={'Content-Type': 'application/json',
                                  'User-Agent': get_user_agent()})
    if r.status_code != 200:
        raise Exception('Unauthorized')
    return 'Bearer %s' % r.json()['access_token']


CACHED_VERSION = None


def get_version():
    global CACHED_VERSION

    if not CACHED_VERSION:
        CACHED_VERSION = VersionInfo('shakenfist').version_string()
    return CACHED_VERSION


def get_user_agent():
    return 'Mozilla/5.0 (Ubuntu; Linux x86_64) Shaken Fist/%s' % get_version()


def discover_interfaces():
    mac_to_iface = {
        '00:00:00:00:00:00': 'broadcast'
    }
    iface_to_mac = {}
    vxid_to_mac = {}

    iface_name = None
    iface_name_re = re.compile('^[0-9]+: ([^:]+): <')

    link_ether = None
    link_ether_re = re.compile('^    link/ether (.*) brd .*')

    stdout, _ = execute(None, 'ip addr list')
    for line in stdout.split('\n'):
        line = line.rstrip()

        m = iface_name_re.match(line)
        if m:
            iface_name = m.group(1)
            continue

        m = link_ether_re.match(line)
        if m:
            link_ether = m.group(1)
            mac_to_iface[link_ether] = iface_name
            iface_to_mac[iface_name] = link_ether

            if iface_name.startswith('vxlan-'):
                vxid = int(iface_name.split('-')[1], 16)
                vxid_to_mac[vxid] = link_ether

    return mac_to_iface, iface_to_mac, vxid_to_mac


def ignore_exception(processname, e):
    msg = '[Exception] Ignored error in %s: %s' % (processname, e)
    _, _, tb = sys.exc_info()
    if tb:
        msg += '\n%s' % traceback.format_exc()

    LOG.error(msg)


def _lock_refresher(locks):
    while True:
        db.refresh_locks(locks)
        time.sleep(10)


def execute(locks, command, check_exit_code=[0], env_variables=None):
    LOG.info('Executing %s with locks %s', command, locks)

    if not locks:
        return processutils.execute(
            command, check_exit_code=check_exit_code,
            env_variables=env_variables, shell=True)

    else:
        p = multiprocessing.Process(
            target=_lock_refresher, args=(locks,))
        p.start()

        try:
            return processutils.execute(
                command, check_exit_code=check_exit_code,
                env_variables=env_variables, shell=True)
        finally:
            p.terminate()
            p.join()


def random_macaddr():
    return '02:00:00:%02x:%02x:%02x' % (random.randint(0, 255),
                                        random.randint(0, 255),
                                        random.randint(0, 255))


def noneish(value):
    if not value:
        return True
    if value.lower() == 'none':
        return True
    return False
