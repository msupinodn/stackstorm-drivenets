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


def get_device_info(host, port, username, password):
    conn = ""
    neighbor_info = dict()
    detected_peers = list()
    print(
        f'trying to connect to {host}, port {port}, with username {username}')
    try:
        conn = Netconf(host=host,
                       port=port,
                       user=username,
                       password=password)

        lldp_data = conn.get_lldp_data()
        router_config = conn.get_config()['rpc-reply']['data']['drivenets-top']
        local_hostname = router_config['system']['config-items']['name']
        system_version = conn.system_version()['rpc-reply']['data']['drivenets-top']['system']['oper-items'][
            'system-version']
        lldp_neighbors = lldp_data['rpc-reply']['data']['drivenets-top']['protocols']['lldp']['interfaces']['interface']
        device_names = list()

        for item in lldp_neighbors:
            if item.get('neighbors'):
                local_interface_name = item.get('name')
                remote_interface_name = item.get('neighbors').get('neighbor').get('oper-items').get('port-id')
                remote_system_name = item.get('neighbors').get('neighbor').get('oper-items').get('system-name')
                remote_mgmt_addr = item.get('neighbors').get('neighbor').get('oper-items').get('management-address')
                system_description = item.get('neighbors').get('neighbor').get('oper-items').get('system-description')
                neighbor_info[local_interface_name] = {
                    'local_host_addr': host,
                    'local_system_name': local_hostname,
                    'remote_mgmt_addr': remote_mgmt_addr,
                    'remote_system_name': remote_system_name,
                    'remote_interface_name': remote_interface_name,
                    'local_interface_name': local_interface_name,
                    'system_description': system_description}

                pprint(neighbor_info[local_interface_name])
                device_names.append(remote_system_name)
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

    return local_hostname, neighbor_info, device_names, detected_peers, router_config, system_version


def output_csv(lldp_info):
    for key, value in lldp_info.items():
        for item in value.items():
            print(
                f'{key},{item[1].get("remote_system_name")},{item[1].get("local_interface_name")},{item[1].get("remote_interface_name")}')


@dataclass
class netbox_mapping:
    def run(self):
        pass

    site: str = "SiteA"
    device_roles: str = "router"
    manufacturers: str = "drivenets"
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


def push_netbox(lldp_info, router_config, router_version, all_devices, netbox_conn):
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
            config_template="1",
            platform="1",
            custom_fields={"Config": str(router_config.get(device_name)),
                           "Version": router_version.get(device_name)})

        print(response)
        for _device in list(netbox_conn.dcim.devices.all()):
            if _device.name == device_name:
                current_device_id = _device.id

        for network_interface in details.items():
            response = netbox_conn.dcim.interfaces.create(
                device=current_device_id,
                name=network_interface[-1].get('local_interface_name'),
                enabled=True,
                type="other",
                description=network_interface[-1].get('system_description')
            )

            print(response)

    pprint(all_devices)

    for device_name, details in lldp_info.items():
        if device_name in all_devices:
            all_devices.remove(device_name)
        populating_devices(device_name, details)

    for device_name in all_devices:
        populating_devices(device_name, {})

    for links in lldp_info.values():
        for link in links.values():
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

    pprint(all_devices)
    return True


class drivenets(Action):
    def run(self, hosts, netbox_url, netbox_secret):
        lldp_info = dict()
        router_config = dict()
        router_version = dict()
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
                hostname, neighbor_info, all_devices, detected_peers, config, system_version = get_device_info(
                    **device_access)
                lldp_info[hostname] = neighbor_info
                router_config[hostname] = config
                router_version[hostname] = system_version
            except (ValueError, TypeError) as error:
                print(f'failed to read line {device} - {error}')

        success = push_netbox(lldp_info, router_config, router_version, list(set(all_devices)), netbox_conn)
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
        "password": "ansible"
    }
]''', netbox_url=netbox_url, netbox_secret=netbox_secret)
