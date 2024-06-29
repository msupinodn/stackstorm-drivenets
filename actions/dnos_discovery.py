import pynetbox

from pprint import pprint
import ipaddress
import json
import os
import sys
from dataclasses import dataclass
from lib.netconf_conn import Netconf
import shutil

try:
    from st2common.runners.base_action import Action
except:
    import logging


    class Action(object):
        def __init__(self, *args, **kwargs):
            self.logger = logging.getLogger(__name__)
            logging.basicConfig(stream=sys.stdout, level=logging.INFO)


class drivenets(Action):

    def get_device_info(self, host, port, username, password, conn=None):
        neighbor_info = dict()
        device_details = dict()
        detected_peers = list()

        self.logger.info(f'trying to connect to {host}, port {port}, with username {username}')
        try:
            discovered_device_names = list()

            conn = Netconf(host=host,
                           port=port,
                           user=username,
                           password=password)

            drivenets_top_info = conn.get_config()['rpc-reply']['data']['drivenets-top']
            local_hostname = conn.system_info()['rpc-reply']['data']['drivenets-top']['system']['oper-items']['name']

            device_details['router_config'] = drivenets_top_info
            device_details['host_addr'] = host

            device_details['local_hostname'] = local_hostname
            device_details['system_type'] = \
                conn.system_info()['rpc-reply']['data']['drivenets-top']['system']['oper-items']['system-type']
            device_details['system_version'] = \
                conn.system_info()['rpc-reply']['data']['drivenets-top']['system']['oper-items'][
                    'system-version']

            lldp_neighbors = \
                conn.get_lldp_data()['rpc-reply']['data']['drivenets-top']['protocols']['lldp']['interfaces'][
                    'interface']

            for item in lldp_neighbors:
                if item.get('neighbors'):
                    local_interface_name = item.get('name')
                    remote_interface_name = item.get('neighbors').get('neighbor').get('oper-items').get('port-id')
                    remote_system_name = item.get('neighbors').get('neighbor').get('oper-items').get('system-name')
                    remote_mgmt_addr = item.get('neighbors').get('neighbor').get('oper-items').get('management-address')
                    system_description = item.get('neighbors').get('neighbor').get('oper-items').get(
                        'system-description')
                    neighbor_info[local_interface_name] = {
                        'local_system_name': local_hostname,
                        'remote_mgmt_addr': remote_mgmt_addr,
                        'remote_system_name': remote_system_name,
                        'remote_interface_name': remote_interface_name,
                        'local_interface_name': local_interface_name,
                        'system_description': system_description}

                    # self.logger.info(neighbor_info[local_interface_name])
                    discovered_device_names.append(remote_system_name)
                    try:
                        if ipaddress.ip_address(remote_mgmt_addr):
                            detected_peers.append(remote_mgmt_addr)
                    except ValueError:
                        pass
            self.logger.info(discovered_device_names)
        except:
            try:
                if conn:
                    conn.close()
            except:
                pass
            return

        finally:
            if conn:
                conn.close()

        return local_hostname, device_details, neighbor_info, discovered_device_names, detected_peers

    def run(self, hosts, output_filename="/tmp/dnos_discovery.json"):
        if os.path.exists('/tmp/nrx/'):
            shutil.rmtree('/tmp/nrx/')

        if os.path.exists(output_filename):
            os.unlink(output_filename)

        device_info = dict()
        devices = json.loads(hosts)

        for device in devices:
            try:
                device_access = {"host": device['host'],
                                 "port": device['port'],
                                 "username": device['username'],
                                 "password": device['password']}
                hostname, _device_details, _neighbor_info, all_devices, detected_peers = \
                    self.get_device_info(**device_access)
                device_info[hostname] = dict()
                device_info[hostname]['host_addr'] = _device_details.get('host_addr')
                device_info[hostname]['lldp_info'] = _neighbor_info
                device_info[hostname]['router_config'] = _device_details.get('router_config')
                device_info[hostname]['system_type'] = _device_details.get('system_type')
                device_info[hostname]['system_version'] = _device_details.get('system_version')

                for detected_device in all_devices:
                    if not device_info.get(detected_device):
                        device_info[detected_device] = dict()

            except (ValueError, TypeError) as error:
                self.logger.info(f'failed to read line {device} - {error}')

        try:
            self.action_service.set_value(name='dnos_info', value=json.dumps(device_info))
        except AttributeError:
            self.logger.info("cant user action_service, fallback to file")
            with open(output_filename, 'w') as f:
                f.write(json.dumps(device_info))


if __name__ == "__main__":
    netbox_url = "http://100.64.6.154:8000"
    netbox_secret = "3cb50016a9e0bcd3614947d93c3551a198260877"
    runclass = drivenets(Action)
    runclass.run(hosts='''[
    {
        "host": "100.64.5.54",
        "port": "830",
        "username": "ansible",
        "password": "ansible",
        "hostname": "RES-SA-5"
    },
    {
        "host": "100.64.5.224",
        "port": "830",
        "username": "ansible",
        "password": "ansible",
        "hostname": "DAL01"
    },
    {
        "host": "100.64.0.67",
        "port": "830",
        "username": "ansible",
        "password": "ansible",
        "hostname": "ATL01"
    }
]''')
