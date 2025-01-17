# Copyright 2020 Michael Still

import time
import uuid

from shakenfist.config import config
from shakenfist import constants
from shakenfist import etcd
from shakenfist import logutil


LOG, _ = logutil.setup(__name__)

#####################################################################
# Locks
#####################################################################


def get_lock(objecttype, subtype, name, ttl=60, timeout=constants.ETCD_ATTEMPT_TIMEOUT,
             relatedobjects=None, log_ctx=LOG, op=None):
    return etcd.get_lock(objecttype, subtype, name, ttl=ttl, timeout=timeout,
                         log_ctx=log_ctx, op=op)


def refresh_lock(lock, relatedobjects=None, log_ctx=LOG):
    if lock:
        etcd.refresh_lock(lock, log_ctx=log_ctx)


def refresh_locks(locks, relatedobjects=None, log_ctx=LOG):
    if locks:
        for lock in locks:
            refresh_lock(lock, log_ctx=log_ctx)


def get_existing_locks():
    return etcd.get_existing_locks()


#####################################################################
# IPManagers
#####################################################################


def get_ipmanager(network_uuid):
    ipm = etcd.get('ipmanager', None, network_uuid)
    if not ipm:
        raise Exception('IP Manager not found for network %s' % network_uuid)
    return ipm


def persist_ipmanager(network_uuid, data):
    etcd.put('ipmanager', None, network_uuid, data)


def delete_ipmanager(network_uuid):
    etcd.delete('ipmanager', None, uuid)

#####################################################################
# Events
#####################################################################


def add_event(object_type, object_uuid, operation, phase, duration, message):
    if config.ENABLE_EVENTS:
        t = time.time()
        LOG.with_fields(
            {
                object_type: object_uuid,
                'fqdn': config.NODE_NAME,
                'operation': operation,
                'phase': phase,
                'duration': duration,
                'message': message
            }).info('Added event')
        etcd.put(
            'event/%s' % object_type, object_uuid, t,
            {
                'timestamp': t,
                'object_type': object_type,
                'object_uuid': object_uuid,
                'fqdn': config.NODE_NAME,
                'operation': operation,
                'phase': phase,
                'duration': duration,
                'message': message
            })


def get_events(object_type, object_uuid):
    for _, m in etcd.get_all('event/%s' % object_type, object_uuid,
                             sort_order='ascend'):
        yield m


#####################################################################
# Namespaces
#####################################################################


def list_namespaces():
    for _, value in etcd.get_all('namespace', None):
        yield value


def get_namespace(namespace):
    return etcd.get('namespace', None, namespace)


def persist_namespace(namespace, data):
    etcd.put('namespace', None, namespace, data)


def delete_namespace(namespace):
    etcd.delete('namespace', None, namespace)

#####################################################################
# Metadata
#####################################################################


def get_metadata(object_type, name):
    return etcd.get('metadata', object_type, name)


def persist_metadata(object_type, name, metadata):
    etcd.put('metadata', object_type, name, metadata)


def delete_metadata(object_type, name):
    etcd.delete('metadata', object_type, name)
