# Copyright 2020 Michael Still

import importlib
import json
import logging
from logging import handlers as logging_handlers
from pbr.version import VersionInfo
import re
import requests
import time

from oslo_concurrency import processutils

from shakenfist import db
from shakenfist import etcd


LOG = logging.getLogger(__file__)
LOG.setLevel(logging.DEBUG)
LOG.addHandler(logging_handlers.SysLogHandler(address='/dev/log'))


class RecordedOperation():
    def __init__(self, operation, object):
        self.operation = operation
        self.object = object

    def __enter__(self):
        self.start_time = time.time()
        LOG.info('%s: Start %s' % (self.object, self.operation))

        object_type, object_uuid = self.get_describing_tuple()
        db.add_event(object_type, object_uuid,
                     self.operation, 'start', None, None)
        return self

    def __exit__(self, *args):
        duration = time.time() - self.start_time
        LOG.info('%s: Finish %s, duration %.02f seconds'
                 % (self.object, self.operation,
                    duration))

        object_type, object_uuid = self.get_describing_tuple()
        db.add_event(object_type, object_uuid,
                     self.operation, 'finish', duration, None)

    def get_describing_tuple(self):
        if self.object:
            if isinstance(self.object, str):
                object_type = 'null'
                object_uuid = self.object
            else:
                object_type, object_uuid = self.object.get_describing_tuple()
        else:
            object_type = 'null'
            object_uuid = 'null'

        return object_type, object_uuid


def check_for_interface(name):
    _, stderr = processutils.execute(
        'ip link show %s' % name, check_exit_code=[0, 1], shell=True)
    return not stderr.rstrip('\n').endswith(' does not exist.')


def get_interface_addresses(namespace, name):
    in_namespace = ''
    if namespace:
        in_namespace = 'ip netns exec %s ' % namespace

    stdout, _ = processutils.execute(
        '%(in_namespace)sip addr show %(name)s'
        % {
            'in_namespace': in_namespace,
            'name': name
        },
        check_exit_code=[0, 1], shell=True)
    if not stdout:
        return

    inet_re = re.compile(r' +inet (.*)/[0-9]+.*')
    for line in stdout.split('\n'):
        m = inet_re.match(line)
        if m:
            yield m.group(1)

    return


def nat_rules_for_ipblock(ipblock):
    out, _ = processutils.execute(
        'iptables -t nat -L POSTROUTING -n -v', shell=True)
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


def get_admin_api_token(base_url):
    auth_url = base_url + '/auth'
    LOG.info('Fetching admin auth token from %s' % auth_url)
    password = etcd.get('passwords', None, 'all')['passwords'][0]
    r = requests.request('POST', auth_url,
                         data=json.dumps({
                             'namespace': 'all',
                             'password': password
                         }),
                         headers={'Content-Type': 'application/json',
                                  'User-Agent': get_user_agent()})
    if r.status_code != 200:
        raise Exception('Unauthorized')
    token = 'Bearer %s' % r.json()['access_token']
    LOG.info('Admin auth token is %s' % token)
    return token


def get_user_agent():
    sf_version = VersionInfo('shakenfist').version_string()
    return 'Mozilla/5.0 (Ubuntu; Linux x86_64) ShakenFist/%s' % sf_version
