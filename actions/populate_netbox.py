import pynetbox
import sys

import json
from dataclasses import dataclass

try:
    from st2common.runners.base_action import Action
except:
    import logging


    class Action(object):
        def __init__(self, *args, **kwargs):
            self.logger = logging.getLogger(__name__)
            logging.basicConfig(stream=sys.stdout, level=logging.INFO)


@dataclass
class netbox_mapping:
    def run(self):
        pass

    site: str = "SiteA"
    device_roles: str = "Router"
    device_roles_color: str = "Red"
    manufacturers: str = "DRIVENETS"
    device_types: str = "dnos"
    model: str = "dnos_router"
    dnos_config: str = "dnos_config"
    dnos_version: str = "dnos_version"


class drivenets(Action):
    def setup_netbox(self, netbox_conn):
        if not netbox_conn.extras.custom_fields.filter(q=netbox_mapping.dnos_config):
            netbox_conn.extras.custom_fields.create(
                {"object_types": ["dcim.device"], "type": "text", "name": netbox_mapping.dnos_config})
        if not netbox_conn.extras.custom_fields.filter(q=netbox_mapping.dnos_version):
            netbox_conn.extras.custom_fields.create(
                {"object_types": ["dcim.device"], "type": "text", "name": netbox_mapping.dnos_version})

        if not netbox_conn.dcim.sites.get(name=netbox_mapping.site):
            netbox_conn.dcim.sites.create({"name": netbox_mapping.site, "slug": netbox_mapping.site.lower()})

        if not netbox_conn.dcim.device_roles.get(name="unknown"):
            netbox_conn.dcim.device_roles.create(
                {"name": "unknown", "slug": "unknown"})

        if not netbox_conn.dcim.manufacturers.get(name="unknown"):
            netbox_conn.dcim.manufacturers.create(
                {"name": "unknown", "slug": "unknown"})

        if not netbox_conn.dcim.device_types.get(model="unknown"):
            netbox_conn.dcim.device_types.create([{
                "model": "unknown",
                "manufacturer": netbox_conn.dcim.manufacturers.get(name="unknown").id,
                "slug": "unknown"
            }])

        if not netbox_conn.dcim.platforms.get(q="unknown"):
            netbox_conn.dcim.platforms.create(name="unknown", slug="unknown")

        if not netbox_conn.dcim.platforms.get(q="DNOS"):
            netbox_conn.dcim.platforms.create(name="DNOS", slug="dnos")

        if not netbox_conn.dcim.device_roles.get(name=netbox_mapping.device_roles):
            netbox_conn.dcim.device_roles.create(
                {"name": netbox_mapping.device_roles, "slug": netbox_mapping.device_roles.lower()})

        if not netbox_conn.dcim.manufacturers.get(name=netbox_mapping.manufacturers):
            netbox_conn.dcim.manufacturers.create(
                {"name": netbox_mapping.manufacturers, "slug": netbox_mapping.manufacturers.lower()})

    def push_netbox(self, device_info, netbox_conn):
        def populating_devices(_device_name, _details):

            def create_device_type(system_type: str):
                if not netbox_conn.dcim.device_types.filter(q=system_type):
                    netbox_conn.dcim.device_types.create([{
                        "model": system_type,
                        "manufacturer": netbox_conn.dcim.manufacturers.get(name="DRIVENETS").id,
                        "slug": system_type.lower()
                    }])

            self.logger.info(f"device_name {_device_name} system_type {_details.get('system_type', 'unknown')}")

            if list(netbox_conn.dcim.devices.filter(q=_device_name)) and not _details:
                self.logger.info(f'device {_device_name} exists, but we dont have details about it, ignoring it')
                return

            for _device in list(netbox_conn.dcim.devices.all()):
                if _device.name == _device_name:
                    self.logger.info(f'deleting {_device_name}')
                    netbox_conn.dcim.devices.delete([_device.id])

            create_device_type(_details.get('system_type'))

            device_type = [x.id for x in netbox_conn.dcim.device_types.filter(q=_details.get('system_type')) if
                           x.display == _details.get('system_type', "unknown")]

            platform = netbox_conn.dcim.platforms.get(q="unknown").id
            device_roles = netbox_conn.dcim.device_roles.get(q="unknown").id

            if _details.get('system_type'):
                platform = netbox_conn.dcim.platforms.get(q="DNOS").id
                device_roles = netbox_conn.dcim.device_roles.get(q="router").id

            self.logger.info(f'adding DNOS device {_device_name} to NetBox, type {device_type}')
            self.logger.info(f"device_type {device_type}, system_type {_details.get('system_type')}")

            response = netbox_conn.dcim.devices.create(
                name=_device_name,
                device_type=device_type[0],
                role=device_roles,
                site=netbox_conn.dcim.sites.get(name=netbox_mapping.site).id,
                platform=platform,
                custom_fields={netbox_mapping.dnos_config: str(_details.get('router_config')),
                               netbox_mapping.dnos_version: str(_details.get('system_version'))}
            )

            self.logger.info(response)

            for _device in list(netbox_conn.dcim.devices.all()):
                if _device.name == _device_name:
                    current_device_id = _device.id

            netbox_conn.dcim.interfaces.create(
                device=current_device_id,
                name="mgmt0",
                enabled=True,
                type="virtual",
                description="mgmt0"
            )
            netbox_ip = None
            if _details.get("host_addr"):
                device_ipv4_address = f'{_details.get("host_addr")}/32'
                if netbox_conn.ipam.ip_addresses.get(address=device_ipv4_address):
                    netbox_conn.ipam.ip_addresses.delete(
                        [netbox_conn.ipam.ip_addresses.get(address=device_ipv4_address).id])
                interface = netbox_conn.dcim.interfaces.get(name="mgmt0", device=_device_name)
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

            if _details.get('lldp_info'):
                for network_interface in _details.get('lldp_info').items():
                    response = netbox_conn.dcim.interfaces.create(
                        device=current_device_id,
                        name=network_interface[-1].get('local_interface_name'),
                        enabled=True,
                        type="100gbase-x-qsfp28",
                        description=network_interface[-1].get('system_description'),
                        label=f"{network_interface[-1].get('remote_system_name')}-{network_interface[-1].get('remote_interface_name')}"
                    )

                self.logger.info(response)

        # Add managed devices
        for device_name, details in device_info.items():
            populating_devices(device_name, details)

        # clear unterminated cables
        empty_cables = list()
        for cable in netbox_conn.dcim.cables.filter(unterminated=True):
            empty_cables.append(cable)
        if empty_cables:
            netbox_conn.dcim.cables.delete(empty_cables)

        # add cable links
        for device in device_info.values():
            if device.get('lldp_info'):
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
                            self.logger.info(data_input)
                            netbox_conn.dcim.cables.create(data_input)
                    except Exception as err:
                        self.logger.info(err)

        return True

    def run(self, input_filename, netbox_url, netbox_secret):
        # netbox_conn = pynetbox.api(url=netbox_url,
        # token = netbox_conn.create_token("admin", "admin")

        netbox_conn = pynetbox.api(url=netbox_url,
                                   token=netbox_secret)

        self.setup_netbox(netbox_conn)

        try:
            device_info = json.loads(self.action_service.get_value('dnos_info'))
        except AttributeError:
            self.logger.info("cant user action_service, fallback to file")
            with open(input_filename, 'r') as f:
                device_info = json.load(f)

        success = self.push_netbox(device_info, netbox_conn)
        if success:
            self.logger.info('Action successfully completed')
        else:
            self.logger.error('Action failed...')


if __name__ == "__main__":
    netbox_url = "http://100.64.6.154:8000"
    netbox_secret = "3cb50016a9e0bcd3614947d93c3551a198260877"
    runclass = drivenets(Action)
    runclass.run("/tmp/dnos_discovery.json", netbox_url=netbox_url, netbox_secret=netbox_secret)
