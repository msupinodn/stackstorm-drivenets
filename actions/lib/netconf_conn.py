import xmltodict
from ncclient.operations.rpc import RPCError
from ncclient import manager
from ncclient.xml_ import NCElement
from typing import Optional, Tuple, Dict
import logging

log = logging.getLogger(__name__)


class DeviceConnectionException(Exception):
    pass


class DeviceCommitException(Exception):
    pass


class DeviceGetException(Exception):
    pass


class Netconf:
    def __init__(self, host: str, port: int, user: str, password: str):
        self.host: str = host
        self.port: int = port
        self.user: str = user
        self.password: str = password
        self.conn: manager.Manager | None = None

        try:
            log.info(f"Connecting via netconf device {host}:{port}...")
            self.conn = manager.connect(host=host,
                                        port=port,
                                        username=user,
                                        password=password,
                                        timeout=60,
                                        device_params={'name': 'alu'},
                                        hostkey_verify=False)
            log.info("Connection established.")
        except Exception:
            log.error("Error encountered while trying to open connection to device.")
            raise DeviceConnectionException(f"Couldn't connect to device {host}:{port}")

    def close(self):
        if self.conn is None:
            return

        try:
            self.conn.close_session()
        except Exception as e:
            log.info("Error encountered while trying to close existing session.")
            # raise DeviceConnectionException(f"Error disconnecting from device: {str(e)}")

    def commit(self):
        if self.conn is None:
            raise DeviceConnectionException("No connection to device.")
        try:
            self.conn.commit()
        except RPCError as e:
            if e.message == 'Commit failed: empty commit':
                log.debug('No change, nothing to commit')
                return
            else:
                log.info("Error encountered while trying to commit the configuration.")
                raise DeviceCommitException(f"Error commiting to device: {str(e)}")

    def get_config(self, filter: Optional[Tuple[str, str]] = None) -> Dict:
        # Filter examples:
        # 1. as xpath:   filter = ('xpath', '/config/protocols/ospf')
        # 2. as subtree: filter = ('subtree', '<config><protocols><ospf/></protocols></config>')
        if self.conn is None:
            raise DeviceConnectionException("No connection to device.")
        try:
            result: NCElement = self.conn.get_config(source='running', filter=filter)
            # log.debug(result)
            return xmltodict.parse(str(result))
        except RPCError as e:
            log.info("Error encountered while trying to get the configuration.")
            raise DeviceCommitException(f"Error getting config from device: {str(e)}")

    def get_lldp_data(self) -> Dict:
        if self.conn is None:
            raise DeviceConnectionException("No connection to device.")
        try:
            filter = ("/dn-top:drivenets-top/dn-proto:protocols/dn-lldp:lldp/"
                      "dn-lldp:interfaces")
            result: NCElement = self.conn.get(filter=('xpath', filter))
            return xmltodict.parse(str(result))
        except RPCError as e:
            log.info("Error encountered while trying to get the lldp oper data.")
            raise DeviceGetException(f"Error getting lldp oper from device: {str(e)}")

    def get_lldp_neighbors(self,
                           interface_name: str,
                           namespace: str = "http://drivenets.com/ns/yang/dn-lldp") -> Dict:
        if self.conn is None:
            raise DeviceConnectionException("No connection to device.")
        try:
            filter = ("/dn-top:drivenets-top/dn-proto:protocols/dn-lldp:lldp/"
                      f"dn-lldp:interfaces/dn-lldp:interface[dn-lldp:name='{interface_name}']/"
                      "dn-lldp:neighbors/dn-lldp:neighbor/dn-lldp:oper-items/dn-lldp:neighbors")
            result: NCElement = self.conn.get(filter=('xpath', filter))
            return xmltodict.parse(str(result))
        except RPCError as e:
            log.info("Error encountered while trying to get the lldp neighbors.")
            raise DeviceGetException(f"Error getting lldp neighbors from device: {str(e)}")

    def get_isis_data(self) -> Dict:
        if self.conn is None:
            raise DeviceConnectionException("No connection to device.")
        try:
            filter = ("/dn-top:drivenets-top/dn-proto:protocols/protocols-isis")
            result: NCElement = self.conn.get(filter=('xpath', filter))
            return xmltodict.parse(str(result))
        except RPCError as e:
            log.info("Error encountered while trying to get the isis oper data.")
            raise DeviceGetException(f"Error getting isis oper data from device: {str(e)}")

    def get_isis_neighbors(self, instance_name: str) -> Dict:
        if self.conn is None:
            raise DeviceConnectionException("No connection to device.")
        try:
            filter = (f"/dn-top:drivenets-top/dn-proto:protocols/protocols-isis/"
                      f"protocol-isis[instance='{instance_name}']/oper-items/adjacencies/neighbor")
            result: NCElement = self.conn.get(filter=('xpath', filter))
            return xmltodict.parse(str(result))
        except RPCError as e:
            log.info("Error encountered while trying to get the isis neighbors.")
            raise DeviceGetException(f"Error getting isis neighbors from device: {str(e)}")

    def get_bfd_sessions(self) -> Dict:
        if self.conn is None:
            raise DeviceConnectionException("No connection to device.")
        try:
            filter = "/dn-top:drivenets-top/dn-proto:protocols/bfd/bfd-sessions/bfd-session"
            result: NCElement = self.conn.get(filter=('xpath', filter))
            return xmltodict.parse(str(result))
        except RPCError as e:
            log.info("Error encountered while trying to get the bfd sessions.")
            raise DeviceGetException(f"Error getting bfd sessions from device: {str(e)}")

    def get_bgp_data(self) -> Dict:
        if self.conn is None:
            raise DeviceConnectionException("No connection to device.")
        try:
            filter = ("/dn-top:drivenets-top/dn-network-services:network-services/"
                      "dn-vrf:vrfs/dn-vrf:vrf/dn-vrf:protocols/bgp")
            result: NCElement = self.conn.get(filter=('xpath', filter))
            return xmltodict.parse(str(result))
        except RPCError as e:
            log.info("Error encountered while trying to get the bgp oper data.")
            raise DeviceGetException(f"Error getting bgp oper data from device: {str(e)}")

    def system_info(self) -> Dict:
        if self.conn is None:
            raise DeviceConnectionException("No connection to device.")
        try:
            filter = ("/dn-top:drivenets-top/system/oper-items")
            result: NCElement = self.conn.get(filter=('xpath', filter))
            return xmltodict.parse(str(result))
        except RPCError as e:
            log.info("Error encountered while trying to get the system oper data.")
            raise DeviceGetException(f"Error getting bgp oper data from device: {str(e)}")

    def interfaces_info(self) -> Dict:
        if self.conn is None:
            raise DeviceConnectionException("No connection to device.")
        try:
            filter = ("/dn-top:drivenets-top/interfaces/interface[name='mgmt0']/ipv4/addresses")
            result: NCElement = self.conn.get(filter=('xpath', filter))
            return xmltodict.parse(str(result))
        except RPCError as e:
            log.info("Error encountered while trying to get the interfaces data.")
            raise DeviceGetException(f"Error getting bgp oper data from device: {str(e)}")
