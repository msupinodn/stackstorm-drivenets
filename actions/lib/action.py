from st2common.runners.base_action import Action
from ncclient import manager


class DrivenetsBaseAction(Action):
    def __init__(self, config):
        self.host: str = self.config['router_ip']
        self.port: int = self.config['port']
        self.user: str = self.config['username']
        self.password: str = self.config['password']
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

        return self.conn
