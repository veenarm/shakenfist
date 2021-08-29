import copy
import ipaddress
import itertools
import time

from oslo_concurrency import processutils

from shakenfist import baseobject
from shakenfist.baseobject import DatabaseBackedObject as dbo
from shakenfist.config import config
from shakenfist.daemons import daemon
from shakenfist import db
from shakenfist import exceptions
from shakenfist import instance
from shakenfist.ipmanager import IPManager
from shakenfist import logutil
from shakenfist import net
from shakenfist import networkinterface
from shakenfist.networkinterface import NetworkInterface
from shakenfist.tasks import (
    DeployNetworkTask,
    DestroyNetworkTask,
    NetworkTask,
    RemoveDHCPNetworkTask,
    RemoveNATNetworkTask,
    UpdateDHCPNetworkTask,
    NetworkInterfaceTask,
    FloatNetworkInterfaceTask,
    DefloatNetworkInterfaceTask)
from shakenfist.util import network as util_network


LOG, _ = logutil.setup(__name__)

EXTRA_VLANS_HISTORY = {}


class Monitor(daemon.Daemon):
    def _maintain_networks(self):
        LOG.info('Maintaining networks')

        # Discover what networks are present
        _, _, vxid_to_mac = util_network.discover_interfaces()

        # Determine what networks we should be on
        host_networks = []
        seen_vxids = []

        if not util_network.is_network_node():
            # For normal nodes, just the ones we have instances for. We need
            # to use the more expensive interfaces_for_instance() method of
            # looking up instance interfaces here if the instance cachce hasn't
            # been populated yet (i.e. the instance is still being created)
            for inst in instance.Instances([instance.this_node_filter,
                                            instance.active_states_filter]):
                ifaces = inst.interfaces
                if not ifaces:
                    ifaces = list(
                        networkinterface.interfaces_for_instance(inst))

                for iface_uuid in ifaces:
                    ni = networkinterface.NetworkInterface.from_db(iface_uuid)
                    if not ni:
                        LOG.with_instance(
                            inst).with_networkinterface(
                            iface_uuid).error('Network interface does not exist')
                    elif ni.network_uuid not in host_networks:
                        host_networks.append(ni.network_uuid)
        else:
            # For network nodes, its all networks
            for n in net.Networks([baseobject.active_states_filter]):
                bad = False
                try:
                    netblock = ipaddress.ip_network(n.netblock)
                    if netblock.num_addresses < 8:
                        bad = True
                except ValueError:
                    bad = True

                if bad:
                    LOG.with_network(n.uuid).error(
                        'Network netblock is invalid, deleting network.')
                    netobj = net.Network.from_db(n.uuid)
                    netobj.delete()
                    continue

                host_networks.append(n.uuid)

                # Network nodes also look for interfaces for absent instances
                # and delete them
                t = time.time()
                for ni in networkinterface.interfaces_for_network(n):
                    inst = instance.Instance.from_db(ni.instance_uuid)
                    if not inst:
                        ni.delete()
                        LOG.with_instance(
                            ni.instance_uuid).with_networkinterface(
                            ni.uuid).info('Deleted stray network interface for missing instance')
                    else:
                        s = inst.state
                        if (s.update_time + 30 < t and
                                s.value in [dbo.STATE_DELETED, dbo.STATE_ERROR, 'unknown']):
                            ni.delete()
                            LOG.with_instance(
                                ni.instance_uuid).with_networkinterface(
                                ni.uuid).info('Deleted stray network interface')

        # Ensure we are on every network we have a host for
        for network in host_networks:
            try:
                n = net.Network.from_db(network)
                if not n:
                    continue

                seen_vxids.append(n.vxid)

                if time.time() - n.state.update_time < 60:
                    # Network state changed in the last minute, punt for now
                    continue

                if not n.is_okay():
                    if util_network.is_network_node():
                        LOG.with_network(n).info(
                            'Recreating not okay network on network node')
                        n.create_on_network_node()

                        # If the network node was missing a network, then that implies
                        # that we also need to re-create all of the floating IPs for
                        # that network.
                        for ni in networkinterface.interfaces_for_network(n):
                            if ni.floating.get('floating_address'):
                                LOG.with_fields(
                                    {
                                        'instance': ni.instance_uuid,
                                        'networkinterface': ni.uuid,
                                        'floating': ni.floating.get('floating_address')
                                    }).info('Refloating interface')
                                n.add_floating_ip(ni.floating.get(
                                    'floating_address'), ni.ipv4)
                    else:
                        LOG.with_network(n).info(
                            'Recreating not okay network on hypervisor')
                        n.create_on_hypervisor()

                n.ensure_mesh()

            except exceptions.LockException as e:
                LOG.warning(
                    'Failed to acquire lock while maintaining networks: %s' % e)
            except exceptions.DeadNetwork as e:
                LOG.with_field('exception', e).info(
                    'maintain_network attempted on dead network')
            except processutils.ProcessExecutionError as e:
                LOG.error('Network maintenance failure: %s', e)

        # Determine if there are any extra vxids
        extra_vxids = set(vxid_to_mac.keys()) - set(seen_vxids)

        # We keep a global cache of extra vxlans we've seen before, so that
        # we only warn about them when they've been stray for five minutes.
        global EXTRA_VLANS_HISTORY
        for vxid in copy.copy(EXTRA_VLANS_HISTORY):
            if vxid not in extra_vxids:
                del EXTRA_VLANS_HISTORY[vxid]
        for vxid in extra_vxids:
            if vxid not in EXTRA_VLANS_HISTORY:
                EXTRA_VLANS_HISTORY[vxid] = time.time()

        # Warn of extra vxlans which have been present for more than five minutes
        for vxid in EXTRA_VLANS_HISTORY:
            if time.time() - EXTRA_VLANS_HISTORY[vxid] > 5 * 60:
                LOG.with_field('vxid', vxid).warning(
                    'Extra vxlan present!')

        # And record vxids in the database
        db.persist_node_vxid_mapping(config.NODE_NAME, vxid_to_mac)

    def _process_network_workitem(self, log_ctx, workitem):
        log_ctx = log_ctx.with_network(workitem.network_uuid())
        n = net.Network.from_db(workitem.network_uuid())
        if not n:
            log_ctx.warning('Received work item for non-existent network')
            return

        # NOTE(mikal): there's really nothing stopping us from processing a bunch
        # of these jobs in parallel with a pool of workers, but I am not sure its
        # worth the complexity right now. Are we really going to be changing
        # networks that much?

        #
        # Tasks valid for a network in ANY STATE
        #
        if isinstance(workitem, RemoveDHCPNetworkTask):
            n.remove_dhcp()
            db.add_event('network', workitem.network_uuid(),
                         'network node', 'remove dhcp', None, None)
            return

        if isinstance(workitem, RemoveNATNetworkTask):
            n.remove_nat()
            db.add_event('network', workitem.network_uuid(),
                         'network node', 'remove nat', None, None)
            return

        #
        # Tasks that should NOT operate on a DEAD network
        #
        if n.is_dead() and n.state.value != net.Network.STATE_DELETE_WAIT:
            log_ctx.with_fields({'state': n.state,
                                 'workitem': workitem}).info(
                'Received work item for a dead network and not delete_wait')
            return

        if isinstance(workitem, DestroyNetworkTask):
            interfaces = list(networkinterface.interfaces_for_network(n))
            if interfaces:
                log_ctx.error(
                    'DestroyNetworkTask for network with interfaces: %s',
                    [i.uuid for i in interfaces])
                return
            try:
                n.delete_on_network_node()
                db.add_event('network', workitem.network_uuid(),
                             'network node', 'destroy', None, None)
            except exceptions.DeadNetwork as e:
                log_ctx.with_field('exception', e).warning(
                    'DestroyNetworkTask on dead network')

        #
        # Tasks that should NOT operate on a DEAD or DELETE_WAIT network
        #
        if n.is_dead():
            log_ctx.with_fields({'state': n.state,
                                 'workitem': workitem}).info(
                'Received work item for a dead network')
            return

        if isinstance(workitem, DeployNetworkTask):
            try:
                n.create_on_network_node()
                n.ensure_mesh()
                db.add_event('network', workitem.network_uuid(),
                             'network node', 'deploy', None, None)
            except exceptions.DeadNetwork as e:
                log_ctx.with_field('exception', e).warning(
                    'DeployNetworkTask on dead network')

        elif isinstance(workitem, UpdateDHCPNetworkTask):
            try:
                n.create_on_network_node()
                n.ensure_mesh()
                db.add_event('network', workitem.network_uuid(),
                             'network node', 'update dhcp', None, None)
            except exceptions.DeadNetwork as e:
                log_ctx.with_field('exception', e).warning(
                    'UpdateDHCPNetworkTask on dead network')

    def _process_networkinterface_workitem(self, log_ctx, workitem):
        log_ctx = log_ctx.with_networkinterface(workitem.interface_uuid())
        n = net.Network.from_db(workitem.network_uuid())
        if not n:
            log_ctx.warning('Received work item for non-existent network')
            return

        ni = NetworkInterface.from_db(workitem.interface_uuid())
        if not ni:
            log_ctx.warning(
                'Received work item for non-existent network interface')
            return

        # Tasks that should not operate on a dead or delete waiting network
        if n.is_dead() and n.state.value != net.Network.STATE_DELETE_WAIT:
            log_ctx.with_fields({'state': n.state,
                                 'workitem': workitem}).info(
                'Received work item for a completely dead network')
            return

        if isinstance(workitem, DefloatNetworkInterfaceTask):
            n.remove_floating_ip(ni.floating.get('floating_address'), ni.ipv4)

            db.add_event('interface', ni.uuid, 'api', 'defloat', None, None)
            with db.get_lock('ipmanager', None, 'floating', ttl=120, op='Instance defloat'):
                ipm = IPManager.from_db('floating')
                ipm.release(ni.floating.get('floating_address'))
                ipm.persist()

            ni.floating = None

        # Tasks that should not operate on a dead network
        if n.is_dead():
            log_ctx.with_fields({'state': n.state,
                                 'workitem': workitem}).info(
                'Received work item for a dead network')
            return

        if isinstance(workitem, FloatNetworkInterfaceTask):
            n.add_floating_ip(ni.floating.get('floating_address'), ni.ipv4)

    def _process_network_node_workitems(self):
        jobname, workitem = db.dequeue('networknode')
        try:
            if not workitem:
                time.sleep(0.2)
                return

            log_ctx = LOG.with_field('workitem', workitem)
            if NetworkTask.__subclasscheck__(type(workitem)):
                self._process_network_workitem(log_ctx, workitem)
            elif NetworkInterfaceTask.__subclasscheck__(type(workitem)):
                self._process_networkinterface_workitem(log_ctx, workitem)
            else:
                raise exceptions.UnknownTaskException(
                    'Network workitem was not decoded: %s' % workitem)

        finally:
            if jobname:
                db.resolve('networknode', jobname)

    def _reap_leaked_floating_ips(self):
        # Ensure we haven't leaked any floating IPs (because we use to)
        floating_gateways = []
        for n in net.Networks([baseobject.active_states_filter]):
            if n.floating_gateway:
                floating_gateways.append(n.floating_gateway)
        LOG.info('Found floating gateways: %s' % floating_gateways)

        floating_addresses = []
        for ni in networkinterface.NetworkInterfaces([baseobject.active_states_filter]):
            if ni.floating.get('floating_address'):
                floating_addresses.append(ni.floating.get('floating_address'))
        LOG.info('Found floating addresses: %s' % floating_addresses)

        with db.get_lock('ipmanager', None, 'floating', ttl=120,
                         op='Cleanup leaks'):
            floating_ipm = IPManager.from_db('floating')
            floating_reserved = [
                floating_ipm.get_address_at_index(0),
                floating_ipm.get_address_at_index(1),
                floating_ipm.broadcast_address,
                floating_ipm.network_address
            ]
            LOG.info('Found floating reservations: %s' % floating_reserved)

            leaks = []
            for ip in floating_ipm.in_use:
                if ip not in itertools.chain(floating_gateways,
                                             floating_addresses,
                                             floating_reserved):
                    LOG.error('Floating IP %s has leaked.' % ip)
                    leaks.append(ip)

            for ip in leaks:
                LOG.error('Leaked floating IP %s has been released.' % ip)
                floating_ipm.release(ip)
            floating_ipm.persist()

    def run(self):
        LOG.info('Starting')
        last_management = 0

        while True:
            if util_network.is_network_node():
                self._process_network_node_workitems()
            else:
                management_age = time.time() - last_management
                time.sleep(max(0, 30 - management_age))

            if time.time() - last_management > 30:
                self._maintain_networks()
                if util_network.is_network_node():
                    self._reap_leaked_floating_ips()
                last_management = time.time()
