__title__ = 'SentinelOne integration'
__version__ = '1.0'
__copyright__ = 'Vectra AI, Inc.'
__status__ = 'Production'

import argparse
import logging
import json
import logging.handlers
import os
import sys
from datetime import datetime
try:
    import requests
    import urllib
    import validators
    import vat.vectra as vectra
    from .config import COGNITO_BRAIN, COGNITO_TOKEN, S1_URL, S1_TOKEN, URI, S1_UI_URL
except ImportError as error:
    print("\nMissing import requirements: %s\n" % str(error))

requests.packages.urllib3.disable_warnings()


VC = vectra.VectraClient(COGNITO_BRAIN, token=COGNITO_TOKEN)

S1_HEADER = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-cache',
    'Authorization': 'ApiToken ' + S1_TOKEN
}

# Setup logging
LOG = logging.getLogger(__name__)


def validate_config(func):
    def config_validator():
        if bool(validators.url(COGNITO_BRAIN)):
            return func()
        else:
            raise Exception('Ensure config.py has valid ATP and Vectra config sections located in the following '
                            'directory:\n{}'.format(os.path.dirname(__file__)))

    return config_validator


def obtain_args():
    parser = argparse.ArgumentParser(description='Poll Cognito for tagged hosts, extracts SentinelOne contextual '
                                                 'information.',
                                     prefix_chars='-', formatter_class=argparse.RawTextHelpFormatter,
                                     epilog='')
    parser.add_argument('--tc', type=int, nargs=2, default=False,
                        help='Poll for hosts with threat and certainty scores >=, eg --tc 50 50')
    parser.add_argument('--tcautoblock', type=int, nargs=2, default=False,
                        help='Auto block S1 agents if threat and certainty scores >=, eg --tcautoblock 80 100.')
    parser.add_argument('--tag', type=str, nargs=1, default=False, help='Host Tag for pulling context from SentinelOne')
    parser.add_argument('--blocktag', type=str, nargs=1, default=False)
    parser.add_argument('--unblocktag', type=str, nargs=1, default=False)
    parser.add_argument('--verbose', default=False, action='store_true', help='Verbose logging')

    return parser.parse_args()


def get_s1_agent_tags(ip):
    url = S1_URL + 'agents?networkInterfaceInet__contains=' + ip + URI
    agent = requests.get(url=url, headers=S1_HEADER).json()['data']
    tag_list = []
    if len(agent):
        agent_attrib = ['networkStatus', 'computerName', 'domain', 'infected', 'osName', 'siteName',
                        'lastLoggedInUserName']
        for item in agent_attrib:
            tag_list.append('S1_{it}: {val}'.format(it=item, val=agent[0][item]))
    else:
        tag_list.append('S1_NoAgent')
    return tag_list


def get_s1_agent_id(ip):
    url = S1_URL + 'agents?networkInterfaceInet__contains=' + ip + URI
    agent = requests.get(url=url, headers=S1_HEADER).json()['data']
    if len(agent):
        s1id = agent[0]['id']
        return s1id
    else:
        return


def set_s1_agent(id, status):
    url = S1_URL + 'agents/actions/' + status
    body_s = {
        "filter": {
            "ids": [
                id
            ]
        }
    }
    body = json.dumps(body_s)
    req_response = requests.post(url=url, data=body, headers=S1_HEADER)
    LOG.info('Connection results: {}'.format(req_response.reason))


def get_s1_computer_name(id):
    url = S1_URL + 'agents?ids=' + id + URI
    comp_name = requests.get(url=url, headers=S1_HEADER).json()['data']
    if len(comp_name):
        return comp_name[0]['computerName']
    else:
        return


def gen_s1_threat_url(computer_name):
    long_url = S1_UI_URL + '&filter={"computerName__contains":"\\"' \
                      + computer_name \
                      + '\\"","resolved":"false","timeTitle":"Last%2024%20Hours"}'
    tiny_url = 'http://tinyurl.com/api-create.php'
    full_url = tiny_url + '?' + urllib.parse.urlencode({"url": long_url})
    tiny_url_response = requests.get(full_url)
    return tiny_url_response.text


def poll_vectra(tag=None, tc=None):
    #  Supplied with tag and/or threat/certainty scores, returns dict of host_id:host
    host_dict = {}
    hosts = []

    if tag:
        hosts = VC.get_hosts(state='active', tags=tag).json()['results']

    if tc:
        t, c = tc[0], tc[1]
        hosts = VC.get_hosts(state='active', threat_gte=int(t), certainty_gte=int(c)).json()['results']

    for host in hosts:
        host_dict.update({host['id']: host})

    #  Need to unionize to remove duplicates
    return host_dict

def update_cognito_host_tags(hostid=None, tags=None):
    vc_host_tags = VC.get_host_tags(host_id=hostid).json()['tags']
    
    # Only tags with this prefix are touched. All other tags are untouched.
    tag_prefix_update_allow = "S1"

    untouched_tags = list(filter(lambda t: not t.startswith(tag_prefix_update_allow), vc_host_tags))
    tags.extend(untouched_tags)

    VC.set_host_tags(host_id=hostid, tags=[], append=False)
    VC.set_host_tags(host_id=hostid, tags=tags, append=False)

def add_host_note(hostid, note):
    log_event = "{}: {}".format(datetime.now().strftime("%d%m%y"), note)
    print(log_event)
    VC.set_host_note(host_id=hostid, note=log_event, append=True)

def auto_block_s1_agents(hosts, tc_autoblock, blocktag):
    # Supplied hosts will be auto-blocked, if TC autoblock criteria are met.
    hosts_blocked = []

    for hostid in hosts.keys():
        host_ip_address = hosts[hostid]['last_source']
        host_threat = hosts[hostid]['threat']
        host_certainty = hosts[hostid]['certainty']
        host_tags = hosts[hostid]['tags']

        host_threat_minimum = tc_autoblock[0]
        host_certainty_minimum = tc_autoblock[1]

        if host_threat >= host_threat_minimum and host_certainty >= host_certainty_minimum:
            add_host_note(hostid, 'Auto-blocking S1 agent {} - threat/certainty [{}/{}] => autoblock [{}/{}]'.format(host_ip_address, host_threat, host_certainty, host_threat_minimum, host_certainty_minimum))
            VC.set_host_tags(host_id=hostid, tags=[blocktag], append=True)
            block_s1_agent(host_ip_address)
            hosts_blocked.append(hostid)

    return hosts_blocked

def block_s1_agent(host_ip_address):
    s1_uuid = get_s1_agent_id(host_ip_address)
    print('Blocking S1_ID: {}'.format(s1_uuid))
    set_s1_agent(s1_uuid, 'disconnect')

def unblock_s1_agent(host_ip_address):
    s1_uuid = get_s1_agent_id(host_ip_address)
    print('Unblocking S1_ID: {}'.format(s1_uuid))
    set_s1_agent(s1_uuid, 'connect')

def update_cognito_notes(hostid, notes):
    cognito_note_header = {
                'Content-Type': 'application/json',
                'Authorization': 'Token ' + COGNITO_TOKEN
            }

    cognito_patch_url = COGNITO_BRAIN + '/api/v2/hosts/' + str(hostid)

    payload = {
        "note": "Host threat URL: " + notes
    }
    body = json.dumps(payload)
    cognito_response = requests.patch(url=cognito_patch_url, headers=cognito_note_header, data=body, verify=False)


@validate_config
def main():
    args = obtain_args()

    if len(sys.argv) == 1:
        print('Run s1 -h for help.')
        sys.exit()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    hosts = poll_vectra(args.tag, args.tc)

    for hostid in hosts.keys():
        host_ip_address = hosts[hostid]['last_source']
        print('hosts_id:{}'.format(host_ip_address))
        tag_list = get_s1_agent_tags(host_ip_address)
        if tag_list[0] != 'S1_NoAgent' and tag_list[3] != 'S1_infected: False':
            notes = gen_s1_threat_url(
                get_s1_computer_name(
                    get_s1_agent_id(
                        host_ip_address
                    )
                )
            )

            VC.set_host_note(host_id=hostid, note=notes, append=True)
            update_cognito_notes(hostid, notes)

        # Update Cognito host tags, without touching existing tags.
        update_cognito_host_tags(hostid=hostid, tags=tag_list)

    if args.tcautoblock:
        hosts_blocked = auto_block_s1_agents(hosts, args.tcautoblock, args.blocktag)

        if len(hosts_blocked) > 0:
            print('A total of ' + str(len(hosts_blocked)) + ' are automatically blocked')

    if args.blocktag:
        hosts = poll_vectra(args.blocktag)
        for hostid in hosts.keys():
            host_ip_address = hosts[hostid]['last_source']
            block_s1_agent(host_ip_address)
            tag_list = get_s1_agent_tags(host_ip_address)
            VC.set_host_tags(host_id=hostid, tags=tag_list, append=False)

    if args.unblocktag:
        hosts = poll_vectra(args.unblocktag)
        for hostid in hosts.keys():
            host_ip_address = hosts[hostid]['last_source']
            unblock_s1_agent(host_ip_address)
            tag_list = get_s1_agent_tags(host_ip_address)
            VC.set_host_tags(host_id=hostid, tags=tag_list, append=False)

if __name__ == '__main__':
    main()


