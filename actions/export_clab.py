import re
import sys
import os
import subprocess

# from nrx import main
import nrx

try:
    from st2common.runners.base_action import Action
except:
    import logging


    class Action(object):
        def __init__(self, *args, **kwargs):
            self.logger = logging.getLogger(__name__)


class drivenets(Action):
    def run(self, netbox_url, netbox_secret, template):
        os.environ['NB_API_URL'] = str(netbox_url)
        os.environ['NB_API_TOKEN'] = str(netbox_secret)

        self.logger.info(subprocess.check_output(
            ['nrx', '--config', '/opt/stackstorm/packs/drivenets/etc/nrx/nrx.conf', '--output', template]))


if __name__ == "__main__":
    netbox_url = "http://100.64.6.154:8000"
    netbox_secret = "3cb50016a9e0bcd3614947d93c3551a198260877"
    runclass = drivenets(Action)
    runclass.run(netbox_url=netbox_url, netbox_secret=netbox_secret)
