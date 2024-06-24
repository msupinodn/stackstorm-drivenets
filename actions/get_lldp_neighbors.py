import pynetbox

from pprint import pprint
import ipaddress
import json
from dataclasses import dataclass
from lib.netconf_conn import Netconf

try:
    from st2common.runners.base_action import Action
except:
    import logging


    class Action(object):
        def __init__(self, *args, **kwargs):
            self.logger = logging.getLogger(__name__)


@dataclass
class netbox_mapping:
    def run(self):
        pass

    site: str = "SiteA"
    device_roles: str = "Leaf"
    manufacturers: str = "DRIVENETS"
    device_types: str = "dnos"
    model: str = "dnos_router"


def setup_netbox(netbox_conn):
    if not netbox_conn.dcim.sites.get(name=netbox_mapping.site):
        netbox_conn.dcim.sites.create({"name": netbox_mapping.site, "slug": netbox_mapping.site})

    if not netbox_conn.dcim.device_roles.get(name=netbox_mapping.device_roles):
        netbox_conn.dcim.device_roles.create({"name": netbox_mapping.device_roles, "slug": netbox_mapping.device_roles})

    if not netbox_conn.dcim.manufacturers.get(name="unknown"):
        netbox_conn.dcim.manufacturers.create(
            {"name": "unknown", "slug": "unknown"})

    if not netbox_conn.dcim.manufacturers.get(name=netbox_mapping.manufacturers):
        netbox_conn.dcim.manufacturers.create(
            {"name": netbox_mapping.manufacturers, "slug": netbox_mapping.manufacturers})

    if not netbox_conn.dcim.device_types.get(model="unknown"):
        netbox_conn.dcim.device_types.create([{
            "model": "unknown",
            "manufacturer": netbox_conn.dcim.manufacturers.get(name="unknown").id,
            "slug": "unknown"
        }])

    if not netbox_conn.dcim.device_types.get(model=netbox_mapping.device_types):
        netbox_conn.dcim.device_types.create([{
            "model": "dnos",
            "manufacturer": netbox_conn.dcim.manufacturers.get(name=netbox_mapping.manufacturers).id,
            "slug": "DNOS"
        }])


def get_device_info(host, port, username, password, conn=None):
    neighbor_info = dict()
    device_details = dict()
    detected_peers = list()

    print(f'trying to connect to {host}, port {port}, with username {username}')
    try:
        discovered_device_names = list()

        conn = Netconf(host=host,
                       port=port,
                       user=username,
                       password=password)

        drivenets_top_info = conn.get_config()['rpc-reply']['data']['drivenets-top']

        device_details['router_config'] = drivenets_top_info
        device_details['host_addr'] = host
        device_details['local_hostname'] = drivenets_top_info['system']['config-items']['name']
        device_details['system_version'] = \
            conn.system_version()['rpc-reply']['data']['drivenets-top']['system']['oper-items'][
                'system-version']

        local_hostname = drivenets_top_info['system']['config-items']['name']

        lldp_neighbors = conn.get_lldp_data()['rpc-reply']['data']['drivenets-top']['protocols']['lldp']['interfaces'][
            'interface']

        for item in lldp_neighbors:
            if item.get('neighbors'):
                local_interface_name = item.get('name')
                remote_interface_name = item.get('neighbors').get('neighbor').get('oper-items').get('port-id')
                remote_system_name = item.get('neighbors').get('neighbor').get('oper-items').get('system-name')
                remote_mgmt_addr = item.get('neighbors').get('neighbor').get('oper-items').get('management-address')
                system_description = item.get('neighbors').get('neighbor').get('oper-items').get('system-description')
                neighbor_info[local_interface_name] = {
                    'local_system_name': local_hostname,
                    'remote_mgmt_addr': remote_mgmt_addr,
                    'remote_system_name': remote_system_name,
                    'remote_interface_name': remote_interface_name,
                    'local_interface_name': local_interface_name,
                    'system_description': system_description}

                # pprint(neighbor_info[local_interface_name])
                discovered_device_names.append(remote_system_name)
                try:
                    if ipaddress.ip_address(remote_mgmt_addr):
                        detected_peers.append(remote_mgmt_addr)
                except ValueError:
                    pass
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


def output_csv(lldp_info):
    for key, value in lldp_info.items():
        for item in value.items():
            print(
                f'{key},{item[1].get("remote_system_name")},{item[1].get("local_interface_name")},{item[1].get("remote_interface_name")}')


#        success = push_netbox(device_info, list(set(all_devices)), netbox_conn)

def push_netbox(device_info, all_devices, netbox_conn):
    def populating_devices(device_name, details):
        for _device in list(netbox_conn.dcim.devices.all()):
            if _device.name == device_name:
                print(f'deleting {device_name}')
                netbox_conn.dcim.devices.delete([_device.id])

        device_type = netbox_conn.dcim.device_types.get(q=netbox_mapping.device_types).id
        # if "unknown" in router_version.get(device_name, "unknown"):
        #    device_type = device_type = netbox_conn.dcim.device_types.get(q="unknown").id

        print(f'adding dnos device {device_name} to netbox, type {device_type}')

        response = netbox_conn.dcim.devices.create(
            name=device_name,
            device_type=device_type,
            role=netbox_conn.dcim.device_roles.get(name=netbox_mapping.device_roles).id,
            site=netbox_conn.dcim.sites.get(name=netbox_mapping.site).id,
            platform="4",
            custom_fields={"Config": str(details.get('router_config')),
                           "Version": str(details.get('system_version'))}
        )

        print(response)

        for _device in list(netbox_conn.dcim.devices.all()):
            if _device.name == device_name:
                current_device_id = _device.id

        netbox_conn.dcim.interfaces.create(
            device=current_device_id,
            name="mgmt0",
            enabled=True,
            type="virtual",
            description="mgmt0"
        )
        netbox_ip = None
        if details.get("host_addr"):
            device_ipv4_address = f'{details.get("host_addr")}/32'
            if netbox_conn.ipam.ip_addresses.get(address=device_ipv4_address):
                netbox_conn.ipam.ip_addresses.delete(
                    [netbox_conn.ipam.ip_addresses.get(address=device_ipv4_address).id])
            interface = netbox_conn.dcim.interfaces.get(name="mgmt0", device=device_name)
            netbox_ip = netbox_conn.ipam.ip_addresses.create(address=device_ipv4_address)
            netbox_ip.assigned_object = interface
            netbox_ip.assigned_object_id = interface.id
            netbox_ip.assigned_object_type = 'dcim.interface'
            netbox_ip.save()

        # Assign IP to device mgmt
        if netbox_ip:
            update_device = netbox_conn.dcim.devices.get(current_device_id)
            update_device.primary_ip4 = netbox_ip.id
            update_device.save()

        if details.get('lldp_info'):
            for network_interface in details.get('lldp_info').items():
                response = netbox_conn.dcim.interfaces.create(
                    device=current_device_id,
                    name=network_interface[-1].get('local_interface_name'),
                    enabled=True,
                    type="100gbase-x-qsfp28",
                    description=network_interface[-1].get('system_description'),
                    label=f"{network_interface[-1].get('remote_system_name')}-{network_interface[-1].get('remote_interface_name')}"
                )

            print(response)

    # pprint(all_devices)

    # Add managed devices
    for device_name, details in device_info.items():
        if device_name in all_devices:
            all_devices.remove(device_name)
        populating_devices(device_name, details)

    # Add unmnanaged devices
    for device_name in all_devices:
        populating_devices(device_name, {})

    # add cable links
    for device in device_info.values():
        for link in device['lldp_info'].values():
            try:
                a_id = None
                b_id = None

                a_int = netbox_conn.dcim.interfaces.get(name=link.get('local_interface_name'),
                                                        device=link.get('local_system_name'))
                b_int = netbox_conn.dcim.interfaces.get(name=link.get('remote_interface_name'),
                                                        device=link.get('remote_system_name'))
                if a_int:
                    a_id = str(a_int.id)

                if b_int:
                    b_id = str(b_int.id)

                if a_id and b_id:
                    data_input = {
                        "a_terminations": [
                            {
                                "object_type": "dcim.interface",
                                "object_id": a_id
                            }
                        ],
                        "b_terminations": [
                            {
                                "object_type": "dcim.interface",
                                "object_id": b_id
                            }
                        ]
                    }
                    pprint(data_input)
                    netbox_conn.dcim.cables.create(data_input)
            except Exception as err:
                print(err)

    # pprint(all_devices)
    return True


class drivenets(Action):
    def run(self, hosts, netbox_url, netbox_secret):
        device_info = dict()
        all_devices = list()
        netbox_conn = pynetbox.api(url=netbox_url,
                                   token=netbox_secret)

        setup_netbox(netbox_conn)
        devices = json.loads(hosts)

        for device in devices:
            try:
                device_access = {"host": device['host'],
                                 "port": device['port'],
                                 "username": device['username'],
                                 "password": device['password']}
                hostname, _device_details, _neighbor_info, all_devices, detected_peers = get_device_info(
                    **device_access)
                device_info[hostname] = dict()
                device_info[hostname]['host_addr'] = _device_details.get('host_addr')
                device_info[hostname]['lldp_info'] = _neighbor_info
                device_info[hostname]['router_config'] = _device_details.get('router_config')
                device_info[hostname]['system_version'] = _device_details.get('system_version')
            except (ValueError, TypeError) as error:
                print(f'failed to read line {device} - {error}')

        success = push_netbox(device_info, list(set(all_devices)), netbox_conn)
        if success:
            self.logger.info('Action successfully completed')
        else:
            self.logger.error('Action failed...')


if __name__ == "__main__":
    netbox_url = "http://100.64.6.154:8000"
    netbox_secret = "3cb50016a9e0bcd3614947d93c3551a198260877"
    runclass = drivenets(Action)
    runclass.run(hosts='''[
    {
        "host": "100.64.6.84",
        "port": "830",
        "username": "ansible",
        "password": "ansible",
        "hostname": "DAL00"
    },
    {
        "host": "100.64.6.116",
        "port": "830",
        "username": "ansible",
        "password": "ansible",
        "hostname": "ATL00"  
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
]''', netbox_url=netbox_url, netbox_secret=netbox_secret)
