import random
import time
import json
import traceback
import requests
from requests.auth import HTTPBasicAuth

class YaBGPAgent(object):

    def __init__(self):
        self.session = requests.Session()
        self.peer = None

    def _get(self, path):
        data = self.session.get('http://localhost/v1/' + path, auth=HTTPBasicAuth('admin', 'admin'))
        return data.json()

    def connected(self):
        for _ in range(60):
            data = self._get('peers')
            for peer in data.get('peers', []):
                if peer['fsm'] == 'ESTABLISHED':
                    self.peer = peer
                    return True
        return

    def _build_yabgp_msgs(self, update):
        yabgp_attr_name_conversion = {
            'nexthop': 3, 'origin': 1, 'as_path': 2, 'local_pref': 5 }
        yabgp_msg = {}
        if not self.peer:
            return {}
        nlri = update.get('nlri')
        if nlri:
            attributes = {}
            attr = update['attr']
            for at_name, at_value in attr.items():
                if at_name == 'as_path':
                    at_value = [[1, at_value]]
                if at_name in yabgp_attr_name_conversion:
                    attributes[yabgp_attr_name_conversion[at_name]] = at_value
            yabgp_msg['attr'] = attributes
            yabgp_msg['nlri'] = nlri
        #withdraw = update.get('withdraw')
        #if 'withdraw' in data:
            #yabgp_msg['withdraw'] = withdraw
        return {self.peer['remote_addr']: yabgp_msg}

    def _send_yabgp(self, update):
        yabgp_msg = self._build_yabgp_msgs(update)
        for peer_ip, msg in yabgp_msg.items():
            headers = {'content-type':'application/json'}
            res = self.session.post(
                    'http://localhost/v1/peer/%s/send/update' % peer_ip,
                    data=json.dumps(msg), auth=HTTPBasicAuth('admin', 'admin'),
                    headers=headers)
            print(res)

    def send_update(self, update):
        if self.peer:
            self._send_yabgp(update)


class BgpUpdateGenerator(object):

    def __init__(self, config):
        self.config = config
        self.agent = YaBGPAgent()

    def run(self):
        """Start sending updates."""
        try:
            if not self.agent.connected():
                print('no BGP router is connected')
                return
            time.sleep(1)
            self._send_random_update()
        except (KeyboardInterrupt, Exception):
            traceback.print_exc()

    def _random_nexthop(self):
        if not self.config['nexthop']:
            return None
        return str(random.choice(self.config['nexthop']))

    def _send_random_update(self):
        """generate updates randomly."""
        def random_prefix():
            prefix = ".".join(map(str, (random.randint(0,255) for _ in range(3))))
            prefix += '.0/24'
            return prefix

        def random_prefixes(max_prefix):
            prefixes = []
            for _ in range(random.randint(1, max_prefix)):
                prefixes.append(random_prefix())
            return prefixes

        def random_as_path(max_length=5):
            as_path = [self.config['local_as']]
            for _ in range(random.randint(0, max_length)):
                as_path.append(random.randint(1, 64999))
            return as_path

        def sample(seq, num):
            if len(seq) >= num:
                return random.sample(seq, num)
            else:
                return seq
        sent = 0
        update_per_sec = self.config['rate'] or 1
        update_per_sec = float(update_per_sec)
        announced_prefixes = set()
        while sent < self.config['count'] or self.config['count'] == 0:
            update = {
                'attr': {
                        'nexthop': self._random_nexthop(),
                        'med': random.randint(0, 100),
                        'origin': random.choice(['igp', 'incomplete', 'egp']),
                        'as_path': random_as_path(),
                        'local_pref': random.randint(100, 150),
                        }
                }
            update['nlri'] = []
            update['withdraw'] = []
            if self.config['update_type'] == 'announce':
                update['nlri'] = random_prefixes(self.config['max_prefix'])
                announced_prefixes.update(update['nlri'])
            elif self.config['update_type'] == 'withdraw':
                update['withdraw'] = random_prefixes(self.config['max_prefix'])
            else:
                if random.getrandbits(1):
                    update['withdraw'] = sample(announced_prefixes, self.config['max_prefix'])
                if random.getrandbits(1):
                    update['nlri'] = random_prefixes(self.config['max_prefix'])
                    announced_prefixes.update(update['nlri'])
            self.agent.send_update(update)
            sent += 1
            time.sleep(1/update_per_sec)

DEFAULTS = {
        'live': None,
        'mrt': None,
        'rand': True,
        'peers': ['127.0.0.1:9179/65000'],
        'agent': 'yabgp',
        'count': 0,
        'rate': 0,
        'max_prefix': 1,
        'update_type': 'mixed',
        'nexthop': ['127.0.0.1'],
        'local_as': 65000,
        'local_ip': '127.0.0.1',
        }

def main():
    bgpgen = BgpUpdateGenerator(DEFAULTS)
    bgpgen.run()

if __name__ == '__main__':
    main()

