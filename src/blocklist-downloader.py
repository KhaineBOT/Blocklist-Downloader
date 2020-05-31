################################################################################
#
# This program downloads open source blocklists.
# These are then converted into formats suitable for unbound, squid, firewalld
# bro, and pf.  It makes the following assumptions:
# 1) the unbound configuration uses /etc/unbound/local-blocking-data.conf to
# block domains, as such this program combines all sources into this file
# 2) pf and squid load individual files for blocking
#
################################################################################

#To Do:
# * put in validation to ensure that only appropriate blocklists are loaded into the given applications
# * Downloading of API IOCs
# * Testing of all inputs and outputs

import urllib.request
import ssl
import re
import argparse
import subprocess, shlex
import json

# threat intelligence types
DOMAIN = 'domain'
IP = 'ip'
FILE_HASH = 'file_hash'

# API Keys
PHISHTANK_API_KEY = ''
SHADOWSERVER_API_KEY = ''
VIRUSTOTAL_API_KEY = ''
ALIENVAULT_API_KEY=''

# common regex
IP_REGEX = '\d+\.\d+\.\d+\.\d+'
DOMAIN_REGEX = '(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
JSON = 'json'

# supported output
PF = 'pf'
FIREWALLD = 'firewalld'
SQUID = 'squid'
BRO = 'bro'
UNBOUND = 'unbound'

IPV4_ADDR = '0.0.0.0'
IPV6_ADDR = '::1'

# blocklist information
blocklists = {
    'abuse.ch Zeus Tracker (Domain)': {
        'id': 'abusezeusdomain',
        'type': DOMAIN,
        'url':	'https://zeustracker.abuse.ch/blocklist.php?download=baddomains',
        'regex' : '',
        'blocklist' : []
    },
    'abuse.ch Zeus Tracker (URL)': {
        'id': 'abusezeusURL',
        'type': DOMAIN,
        'url':	'https://zeustracker.abuse.ch/blocklist.php?download=compromised',
        'regex' : '',
        'blocklist' : []
    },
    'abuse.ch Zeus Tracker (IP)': {
        'id': 'abusezeusip',
        'type': IP,
        'url': 'https://zeustracker.abuse.ch/blocklist.php?download=badips',
        'regex' : '',
        'blocklist' : []
    },
    'abuse.ch Palevo Tracker (Domain)': {
        'id': 'abusepalevodomain',
        'type': DOMAIN,
        'url':	'https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist',
        'regex' : '',
        'blocklist' : []
    },
    'abuse.ch Palevo Tracker (IP)': {
        'id': 'abusepalevoip',
        'type': IP,
        'url':	'https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist',
        'regex' : '',
        'blocklist' : []
    },
    'malwaredomains.com IP List': {
        'id': 'malwaredomainsip',
        'type': IP,
        'url': 'http://www.malwaredomainlist.com/hostslist/ip.txt',
        'regex' : '',
        'blocklist' : []
    },
    'PhishTank': {
        'id': 'phishtank',
        'type': DOMAIN,
        'url': 'http://data.phishtank.com/data/online-valid.json',
        'regex' : JSON,
        'blocklist' : []
    },
    'malc0de.com List': {
        'id': 'malc0de',
        'type': IP,
        'url': 'http://malc0de.com/bl/IP_Blacklist.txt',
        'regex' : '',
        'blocklist' : []
    },
    'TOR Node List': {
        'id': 'tornodes',
        'type': IP,
        'url': 'http://torstatus.blutmagie.de/ip_list_all.php/Tor_ip_list_ALL.csv',
        'regex' : '',
        'blocklist' : []
    },
    'blocklist.de List': {
        'id': 'blocklistde',
        'type': IP,
        'regex' : '',
        'url': 'http://lists.blocklist.de/lists/all.txt',
    },
        'AlienVault IP Reputation Database': {
        'id': 'alienvault',
        'type': IP,
        'url': 'https://reputation.alienvault.com/reputation.generic',
        'regex' : IP_REGEX,
        'blocklist' : []
    },
    'OpenBL.org Blacklist': {
        'id': 'openbl',
        'type': IP,
        'url': 'http://www.openbl.org/lists/base.txt',
        'regex' : '',
        'blocklist' : []
    },
    'Nothink.org SSH Scanners': {
        'id': 'nothinkssh',
        'type': IP,
        'url': 'http://www.nothink.org/blacklist/blacklist_ssh_week.txt',
        'regex' : '',
        'blocklist' : []
    },
    'Nothink.org Malware IRC Traffic': {
        'id': 'nothinkirc',
        'type': IP,
        'url': 'http://www.nothink.org/blacklist/blacklist_malware_irc.txt',
        'regex' : '',
        'blocklist' : []
    },
    'C.I. Army Malicious IP List': {
        'id': 'ciarmy',
        'type': IP,
        'url': 'http://cinsscore.com/list/ci-badguys.txt',
        'regex' : '',
        'blocklist' : []
    },
    'Emerging Threats': {
        'id': 'emergingthreats',
        'type': IP,
        'url': 'http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
        'regex' : '',
        'blocklist' : []
    },
    'Emerging Threats Bots': {
        'id': 'emergingthreats-bots',
        'type': IP,
        'url': 'http://rules.emergingthreats.net/open/suricata/rules/botcc.rules',
        'regex' : 'IP_REGEX',
        'blocklist' : []
    },
    'Emerging Threats IPs': {
        'id': 'emergingthreats-ips',
        'type': IP,
        'url': 'http://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt',
        'regex' : '',
        'blocklist' : []
    },
    'Emerging Threats DNS': {
        'id': 'emergingthreats-dns',
        'type': DOMAIN,
        'url': 'https://rules.emergingthreats.net/open/suricata/rules/emerging-dns.rules',
        'regex' : '(?i)C2 Domain \.?([^\s\"]+)',
        'blocklist' : []
    },
    'Project Honeypot': {
        'id': 'projecthoneypot',
        'type': IP,
        'url': 'http://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1',
        'regex' : '',
        'blocklist' : []
    },
    'Rulez.sk blocklist': {
        'id': 'rulez.sk',
        'type': IP,
        'url': 'http://danger.rulez.sk/projects/bruteforceblocker/blist.php',
        'regex' : '',
        'blocklist' : []
    },
    'Firehol blocklist': {
        'id': 'firehol',
        'type': IP,
        'url': 'https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset',
        'regex' : '',
        'blocklist' : []
    },
    'Abuse.ch Ransomware': {
        'id': 'ransomware',
        'type': IP,
        'url': 'https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt',
        'regex' : '',
        'blocklist' : []
    },
    'Abuse.ch Ransomware DNS': {
        'id': 'ransomware-dns',
        'type': DOMAIN,
        'url': 'http://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt',
        'regex' : '',
        'blocklist' : []
    },
    'Abuse.ch Ransomware URL': {
        'id': 'ransomware-url',
        'type': DOMAIN,
        'url': 'http://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt',
        'regex' : '',
        'blocklist' : []
    },
    'Binary Defense Systems': {
        'id': 'bindefence',
        'type': IP,
        'url': 'http://www.binarydefense.com/banlist.txt',
        'regex' : '',
        'blocklist' : []
    },
    'Binary Defense Systems': {
        'id': 'badips',
        'type': IP,
        'url': 'https://www.badips.com/get/list/any/2?age=7d',
        'regex' : '',
        'blocklist' : []
    },
    'hpHosts ad-tracking servers': {
        'id': 'hphosts',
        'type': DOMAIN,
        'url': 'http://hosts-file.net/download/hosts.txt',
        'regex' : '',
        'blocklist' : []
    },
    'MVPS': {
        'id' : 'mvps',
        'type' : DOMAIN,
        'url': 'http://winhelp2002.mvps.org/hosts.txt',
        'regex' : '',
        'blocklist' : []
    },
    'malwaredomains.com Domain List': {
        'id': 'malwaredomainsdomain',
        'type': DOMAIN,
        'url': 'http://www.malwaredomainlist.com/hostslist/hosts.txt',
        'regex' : '',
        'blocklist' : []
    },
    'Stevenblack': {
        'id': 'stevenblack',
        'type': DOMAIN,
        'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
        'regex' : '',
        'blocklist' : []
    },
    'pgl.yoyo.org': {
        'id': 'pgl.yoyo.org',
        'type': DOMAIN,
        'url': 'http://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&mimetype=plaintext',
        'regex' : '',
        'blocklist' : []
    },
    'Hosts File Project': {
        'id': 'hostsfileproject',
        'type': DOMAIN,
        'url': 'http://hostsfile.mine.nu/Hosts',
        'regex' : '',
        'blocklist' : []
    },
    'The Cameleon Project': {
        'id': 'cameleonproject',
        'type': DOMAIN,
        'url': 'http://sysctl.org/cameleon/hosts',
        'regex' : '',
        'blocklist' : []
    },
    'AdAway mobile ads': {
        'id': 'adaway',
        'type': DOMAIN,
        'url': 'http://adaway.sufficientlysecure.org/hosts.txt',
        'regex' : '',
        'blocklist' : []
    },
    'Someone Who Cares': {
        'id': 'someonewhocares',
        'type': DOMAIN,
        'url': 'http://someonewhocares.org/hosts/hosts',
        'regex' : '',
        'blocklist' : []
    },
    'pi-hole': {
        'id': 'pi-hole',
        'type': DOMAIN,
        'url': 'https://github.com/pi-hole/pi-hole/blob/master/adlists.default',
        'regex' : '',
        'blocklist' : []
    },
    'adblock': {
        'id': 'adblock',
        'type': DOMAIN,
        'url': 'http://adblock.gjtech.net/?format=unix-hosts',
        'regex' : '',
        'blocklist' : []
    },
    'disconnect-ad': {
        'id': 'disconnect-ad',
        'type': DOMAIN,
        'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt',
        'regex' : '',
        'blocklist' : []
    },
    'disconnect-tracking': {
        'id': 'disconnect-tracking',
        'type': DOMAIN,
        'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt',
        'regex' : '',
        'blocklist' : []
    },
    'Quidsups tracker list': {
        'id': 'quidsup',
        'type': DOMAIN,
        'url' : 'https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt',
        'regex' : '',
        'blocklist' : []
    },
    'Windows 10 telemetry list': {
        'id': 'wintelemetry',
        'type': DOMAIN,
        'url': 'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/win10/spy.txt',
        'regex' : '',
        'blocklist' : []
    },
    'notracking': {
        'id': 'notracking',
        'type': DOMAIN,
        'url': 'https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt',
        'regex' : '',
        'blocklist' : []
    },
    'Nothink.org Malware HTTP Traffic': {
        'id': 'nothinkhttp',
        'type': DOMAIN,
        'url': 'http://www.nothink.org/blacklist/blacklist_malware_http.txt',
        'regex' : '',
        'blocklist' : []
    },
    'isc suspicious domains': {
        'id': 'iscdomains',
        'type': DOMAIN,
        'url': 'https://isc.sans.edu/feeds/suspiciousdomains_Medium.txt',
        'regex' : '',
        'blocklist' : []
    },
    'isc suspicious ip': {
        'id': 'iscip',
        'type': IP,
        'url': 'http://feeds.dshield.org/top10-2.txt',
        'regex' : '',
        'blocklist' : []
    },
    'networksec': {
        'id': 'networksec',
        'type': DOMAIN,
        'url': 'http://www.networksec.org/grabbho/block.txt',
        'regex' : '',
        'blocklist' : []
    },
    'cybercrime-tracker.net': {
        'id': 'cybercrime-ccam',
        'type': DOMAIN,
        'url': 'http://cybercrime-tracker.net/ccam.php',
        'regex': '>([^<]+\.[a-zA-Z]+)</td>\s*<td style=\"background-color: rgb\(11, 11, 11\);\"><a href=\"ccamdetail\.php\?hash=',
        'blocklist' : []
    },
    'bambenekconsulting.com dns': {
        'id': 'bambenekconsulting.com-dns',
        'type': DOMAIN,
        'url': 'http://osint.bambenekconsulting.com/feeds/c2-dommasterlist-high.txt',
        'regex': '(?m)^([^,#]+),Domain used by ([^,/]+)',
        'blocklist' : []
    },
    'bambenekconsulting.com ip': {
        'id': 'bambenekconsulting.com-ip',
        'type': IP,
        'url': 'http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist-high.txt',
        'regex': '(?m)^([\d.]+),IP used by ([^,/]+) C&C',
        'blocklist' : []
    },
    'bambenekconsulting.com dga': {
        'id': 'bambenekconsulting.com-dga',
        'type': DOMAIN,
        'url': 'http://osint.bambenekconsulting.com/feeds/dga-feed.txt',
        'regex': '(?m)^([^,#]+),Domain used by ([^,/]+)',
        'blocklist' : []
    },
    'botscout_1d': {
        'id': 'botscout_1d',
        'type': IP,
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/botscout_1d.ipset',
        'regex' : '',
        'blocklist' : []
    },
    'cinsscore.com': {
        'id': 'cinsscore.com',
        'type': IP,
        'url': 'http://cinsscore.com/list/ci-badguys.txt',
        'regex' : '',
        'blocklist' : []
    },
    'cruzit.com': {
        'id': 'cruzit.com',
        'type': IP,
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cruzit_web_attacks.ipset',
        'regex' : '',
        'blocklist' : []
    },
    'dataplane-sip': {
        'id': 'dataplane-sip',
        'type': IP,
        'url': 'https://dataplane.org/sipinvitation.txt',
        'regex': IP_REGEX,
        'blocklist' : []
    },
    'dataplane-sipquery': {
        'id': 'dataplane-sipquery',
        'type': IP,
        'url': 'https://dataplane.org/sipquery.txt',
        'regex': IP_REGEX,
        'blocklist' : []
    },
    'dataplane-sipregistration': {
        'id': 'dataplane-sipregistration',
        'type': IP,
        'url': 'https://dataplane.org/sipregistration.txt',
        'regex': IP_REGEX,
        'blocklist' : []
    },
    'dataplane-sshc': {
        'id': 'dataplane-sshc',
        'type': IP,
        'url': 'https://dataplane.org/sshclient.txt',
        'regex': IP_REGEX,
        'blocklist' : []
    },
    'dataplane-sshpw': {
        'id': 'dataplane-sshpw',
        'type': IP,
        'url': 'https://dataplane.org/sshpwauth.txt',
        'regex': IP_REGEX,
        'blocklist' : []
    },
    'dataplane-vnc': {
        'id': 'dataplane-vnc',
        'type': IP,
        'url': 'https://dataplane.org/vncrfb.txt',
        'regex': IP_REGEX,
        'blocklist' : []
    },
    'greensnow': {
        'id': 'greensnow',
        'type': IP,
        'url': 'http://blocklist.greensnow.co/greensnow.txt',
        'regex' : '',
        'blocklist' : []
    },
    'otx-c2-iocs': {
        'id': 'otx-c2-iocs',
        'type': IP,
        'url': 'https://raw.githubusercontent.com/Neo23x0/signature-base/39787aaefa6b70b0be6e7dcdc425b65a716170ca/iocs/otx-c2-iocs.txt',
        'regex': IP_REGEX,
        'blocklist' : []
    },
    'malwarepatrol': {
        'id': 'malwarepatrol',
        'type': DOMAIN,
        'url': 'https://lists.malwarepatrol.net/cgi/getfile?receipt=f1417692233&product=8&list=dansguardian',
        'regex' : '',
        'blocklist' : []
    },
    'myip': {
        'id': 'myip',
        'type': IP,
        'url': 'https://myip.ms/files/blacklist/htaccess/latest_blacklist.txt',
        'regex': IP_REGEX,
        'blocklist' : []
    },
    'openphish': {
        'id': 'openphish',
        'type': DOMAIN,
        'url': 'https://openphish.com/feed.txt',
        'regex': '://(.*)',
        'blocklist' : []
    },
    'packetmail': {
        'id': 'packetmail',
        'type': IP,
        'url': 'https://www.packetmail.net/iprep_ramnode.txt',
        'regex': IP_REGEX,
        'blocklist' : []
    },
    'policeman': {
        'id': 'policeman',
        'type': DOMAIN,
        'url': 'https://raw.githubusercontent.com/futpib/policeman-rulesets/master/examples/simple_domains_blacklist.txt',
        'regex' : '',
        'blocklist' : []
    },
    'cybercrime-tracker.net ccpm': {
        'id': 'ccpm',
        'type': DOMAIN,
        'url': 'http://cybercrime-tracker.net/ccpmgate.php',
        'regex' : '',
        'blocklist' : []
    },
    'proxylists': {
        'id': 'proxylists',
        'type': IP,
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/proxylists_1d.ipset',
        'regex' : '',
        'blocklist' : []
    },
    'proxyrss_1d': {
        'id': 'proxyrss_1d',
        'type': IP,
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/proxyrss_1d.ipset',
        'regex' : '',
        'blocklist' : []
    },
    'proxyspy': {
        'id': 'proxyspy_1d',
        'type': IP,
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/proxyspy_1d.ipset',
        'regex' : '',
        'blocklist' : []
    },
    'ri_web_proxies_30d': {
        'id': 'ri_web_proxies_30d',
        'type': IP,
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/ri_web_proxies_30d.ipset',
        'regex' : '',
        'blocklist' : []
    },
    'rutgers.edu': {
        'id': 'rutgers',
        'type': IP,
        'url': 'http://report.rutgers.edu/DROP/attackers',
        'regex' : '',
        'blocklist' : []
    },
    'sblam': {
        'id': 'sblam',
        'type': IP,
        'url': 'http://sblam.com/blacklist.txt',
        'regex' : '',
        'blocklist' : []
    },
    'sblam': {
        'id': 'socks_proxy_7d',
        'type': IP,
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/socks_proxy_7d.ipset',
        'regex' : '',
        'blocklist' : []
    },
    'abuse.ch SSL IPBL': {
        'id': 'sslipbl',
        'type': IP,
        'url': 'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv',
        'regex' : '',
        'blocklist' : []
    },
    'sslproxies_1d': {
        'id': 'sslproxies_1d',
        'type': IP,
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/sslproxies_1d.ipset',
        'regex' : '',
        'blocklist' : []
    },
    'talosintelligence.com': {
        'id': 'talosintelligence.com',
        'type': IP,
        'url': 'http://www.talosintelligence.com/feeds/ip-filter.blf',
        'regex' : '',
        'blocklist' : []
    },
    'Tor exit nodes': {
        'id': 'torproject',
        'type': IP,
        'url': 'https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1',
        'regex' : '',
        'blocklist' : []
    },
    'turris.cz': {
        'id': 'turris.cz',
        'type': IP,
        'url': 'https://www.turris.cz/greylist-data/greylist-latest.csv',
        'regex': IP_REGEX,
        'blocklist' : []
    },
    'urlvir.com': {
        'id': 'urlvir.com',
        'type': DOMAIN,
        'url': 'http://www.urlvir.com/export-hosts/',
        'regex' : '',
        'blocklist' : []
    },
    'vxvault.net': {
        'id': 'vxvault.net',
        'type': DOMAIN,
        'url': 'http://vxvault.net/URL_List.php',
        'regex' : '',
        'blocklist' : []
    },
    'ipsum': {
        'id': 'ipsum',
        'type': IP,
        'url': 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
        'regex': IP_REGEX,
        'blocklist' : []
    },
    'majestic': {
        'id': 'majestic',
        'type': DOMAIN,
        'url': 'http://downloads.majestic.com/majestic_million.csv',
        'regex': DOMAIN,
        'blocklist' : []
    }

}

################################################################################

def loadConfig(configLocation):
    from configparser import ConfigParser

    try:

        config = ConfigParser()
        config.read(configLocation)

    except IOError as e:
            if hasattr(e, 'reason'):
                print (e.reason)

    global PHISHTANK_API_KEY
    global SHADOWSERVER_API_KEY
    global VIRUSTOTAL_API_KEY
    global ALIENVAULT_API_KEY

    PHISHTANK_API_KEY = config.get('API_KEYS','PHISHTANK_API_KEY')
    SHADOWSERVER_API_KEY = config.get('API_KEYS','SHADOWSERVER_API_KEY')
    VIRUSTOTAL_API_KEY =  config.get('API_KEYS','VIRUSTOTAL_API_KEY')
    ALIENVAULT_API_KEY = config.get('API_KEYS', 'ALIENVAULT_API_KEY')

    global output
    global location
    global filename
    global blocklist_names

    output = config.get('main','OUTPUT')
    location = config.get('main','LOCATION')
    filename =  config.get('main','FILENAME')
    blocklist_names = [e.strip() for e in config.get('main','blocklist_names').split(',')]

################################################################################

def retrieve_content(url):
    headers = {}
    headers['User-Agent'] = "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:48.0) Gecko/20100101 Firefox/48.0"

    request = urllib.request.Request(url, headers = headers)
    
    retval = ''

    #download data
    try:
        response = response = urllib.request.urlopen(request)

        retval = response.read()

    except HTTPError as e:
        # do something
        print('Error code: ', e.code)
    except URLError as e:
        # do something
        print('Reason: ', e.reason)
        
    return retval

################################################################################

def processBlocklist(type, url, regex):
    _blocklist = []

    content = retrieve_content(url).decode('utf-8')

    if regex == '':
        _blocklist = re.sub(r'(?m)^\#.*\n?', '', content).split()

    elif regex == DOMAIN_REGEX:
        _blocklist = re.sub(r'(?m)^\#.*\n?', '', content)
        _blocklist = re.findall(DOMAIN_REGEX, blocklists)

    elif regex == IP_REGEX:
        for match in re.finditer(regex, content):
            _blocklist = _blocklist + [match.group(0)]
    elif regex == JSON:

        print ('loading json')

        for key in enumerate(json.loads(content)):

            # The json returns a unicode string that we need to convert to a bytecode string
            _blocklist = _blocklist + [unicode.encode(key[1]['url'],'utf-8')]

    # removes blank lines
    _blocklist = [_f for _f in _blocklist if _f]

    # remove comments
    _blocklist = [x for x in _blocklist if not x.startswith('\#')]

    # remove localhost
    _blocklist = [x for x in _blocklist if x != "127.0.0.1"]
    _blocklist = [x for x in _blocklist if x != "::1"]
    _blocklist = [x for x in _blocklist if x != "localhost"]
    _blocklist = [x for x in _blocklist if x != "0.0.0.0"]

    return _blocklist

################################################################################

def writeBlocklist(blocklists, _file_path, output):

    if output == 'csv':
        try:
            with open(_file_path, 'w') as f:
                for key, value in sorted(blocklists.items()):
                    # download all supported threat intelligence feeds
                    if blocklist_names == None or value['id'] in blocklist_names:
                        for item in value['blocklist']:
                            f.write(item)
                            f.write('\n')
                f.close()
        except IOError as e:
            print (e.reason)

    elif output == PF:
        for key, value in sorted(blocklists.items()):
            
            # download all supported threat intelligence feeds
            if args.blocklist_names == None or value['id'] in args.blocklist_names:

                try:
                    with open(_file_path + value['id'], 'w') as f:
                        for item in value['blocklist']:
                            f.write(item)
                            f.write('\n')
                        f.close()
                except IOError as e:
                        print (e.reason)

    elif output == FIREWALLD:
        print("")
    # the blocklist can be added via the cli without the information being stored in a file before being loaded
        for key, value in sorted(blocklists.items()):

            #download all supported threat intelligence feeds
            if args.blocklist_names == None or value['id'] in args.blocklist_names:

                # write to blocklist
                try:
                    with open(_file_path + value['id'], 'w') as f:
                        for item in value['blocklist']:
                            f.write(item)
                            f.write('\n')
                        f.close()
                except IOError as e:
                        print (e.reason)

    elif output == UNBOUND:
        _filename = 'local-blocking-data.conf'
        _blocklists = []

        for key, value in sorted(blocklists.items()):

            #download all supported threat intelligence feeds
            if args.blocklist_names == None or value['id'] in args.blocklist_names:
                if value['type'] in [DOMAIN, IP]:
                    _blocklists += value['blocklist']

        try:
            with open(_file_path+_filename, 'w') as f:
            
                for _item in _blocklists:
                    f.write('local-data: \"')
                    f.write("%s" % item)
                    f.write(' A ' + IPV4_ADDR + '\"')
                    f.write('\n')
                    
                    f.write('local-data: \"')
                    f.write("%s" % item)
                    f.write(' AAAA ' + IPV6_ADDR + '\"')
                    f.write('\n')
                f.close()
        except IOError as e:
            print (e.reason)
            
    elif output == SQUID:
        #download all supported threat intelligence feeds
        if args.blocklist_names == None or value['id'] in args.blocklist_names:
            if value['type'] in [DOMAIN, IP]:
                try:
                    with open(_file_path + value['id'], 'w') as f:
                        for item in value['blocklist']:
                            f.write(item)
                            f.write('\n')
                        f.close()
                except IOError as e:
                        print (e.reason)
    
    elif output == BRO:
        for key, value in sorted(blocklists.items()):

            #download all supported threat intelligence feeds
            if args.blocklist_names == None or value['id'] in args.blocklist_names:
                blocklists += value['blocklist']

            try:
                    with open(_file_path + value['id'], 'w') as f:

                        for item in value['blocklist']:
                            # correct this to be the correct output expected by Bro Intel Framework
                            f.write("%s" % item)
                            f.write(':')
                            f.write('\n')

                        f.close()
            except IOError as e:
                    print (e.reason)


        print ("Need to finish")
    
################################################################################

def reloadFirewallRules(firewall, _location, _blocklist_names):

    if firewall == PF:

        for key, value in sorted(blocklists.items()):

            print ('/sbin/pfctl -t ' + value['id'] + ' -Tr -f ' + _location+value['id'])
            subprocess.check_call(shlex.split('/sbin/pfctl -t ' + value['id'] + ' -Tr -f ' + _location+value['id']))

    # based on http://www.firewalld.org/2015/12/ipset-support
    if firewall == FIREWALLD:
        subprocess.check_call(shlex.split('/usr/bin/firewall-cmd --permanent --new-ipset=blacklist --type=hash:ip'))

        for key, value in sorted(blocklists.items()):

            # download all supported threat intelligence feeds
            if blocklist_names == None or value['id'] in blocklist_names:
                for indicator in value['blocklist']:
                    subprocess.check_call(shlex.split('/usr/bin/firewall-cmd -add-entry=' + indicator))

        subprocess.check_call(shlex.split('/usr/bin/firewall-cmd --add-rich-rule=rule source ipset=blacklist drop'))

        subprocess.check_call(shlex.split('/usr/bin/firewall-cmd --reload'))

################################################################################

# main

parser = argparse.ArgumentParser(description='Blocklist downloader and importer for squid, unbound and pf')
parser.add_argument('-l', '--location',help='location to store blocklists', required=False)
parser.add_argument('-n', '--blocklist_names',help='specify names of blocklists to download', required=False, type=lambda s: [str(item) for item in s.split(',')])
parser.add_argument('--list',help='lists all of the supported blocklists',required=False, nargs='?', const=True)
parser.add_argument('-o', '--output',help='specify output format', required=False)

args = parser.parse_args()

#sensible defaults
global location
global output
global filename
global configLocation

location = '/root/blocklist/'
output = 'csv'
filename  = 'blocklist.csv'
configLocation  = './blocklist-downloader.conf'

loadConfig(configLocation)

# set location to store intelligence to the one provided by the user
if args.location != None:
    location = args.location

# set the output format
if args.output != None:
        output = args.output

# set the blocklists to download
if args.blocklist_names != None:
    blocklist_names = args.blocklist_names

# if the location is missing the trailing / add one
if not (location.endswith('/')):
    location = location + '/'

# list out all supported threat intelligence feeds
if (args.list):
    print ('Supported blocklists:')
    for key, value in sorted(blocklists.items()):
        print (key + ' url: ' + value['url'])
    exit (0)

for key, value in sorted(blocklists.items()):

    # download all supported threat intelligence feeds
    if blocklist_names == None or value['id'] in blocklist_names:

        print ('downloading: ' + value['id'])

        value['blocklist'] = processBlocklist(value['type'], value['url'], value['regex'])
        
# output into desired format
if args.output == 'csv':
    filename = 'blocklist.csv'
    writeBlocklist(blocklists, location+filename,output)

elif output == PF:
    writeBlocklist(blocklists, location, output)
    subprocess.check_call(shlex.split('/usr/bin/logger -i -t blocklist-downloader reloading pf configuration'))
    reloadFirewallRules(PF, location, blocklist_names)

elif output == FIREWALLD:
    filename = blocklist
    writeBlocklist(blocklists, location, output)
    subprocess.check_call(shlex.split('/usr/bin/logger -i -t blocklist-downloader reloading firewalld configuration'))
    reloadFirewallRules(FIREWALLD, location+filename, blocklist_names)

elif output == UNBOUND:
    writeBlocklist(blocklists, location, output)
    subprocess.check_call(shlex.split('/usr/bin/logger -i -t blocklist-downloader reloading unbound configuration'))
    subprocess.check_call(shlex.split('/usr/sbin/service local_unbound restart'))

elif output == SQUID:
    writeBlocklist(blocklists, location, output)
    subprocess.check_call(shlex.split('/usr/bin/logger -i -t blocklist-downloader reloading squid configuration'))
    subprocess.check_call(shlex.split('/usr/local/sbin/squid -k reconfigure'))

elif output == BRO:
    writeBlocklist(blocklists, location, output)
    subprocess.check_call(shlex.split('/usr/bin/logger -i -t blocklist-downloader reloading bro configuration'))
    subprocess.check_call(shlex.split('/usr/local/bin/broctl install'))

else:
    print ("No output specified, using default output (csv)")
    filename = 'blocklist.csv'
    writeBlocklist(blocklists, location+filename, 'csv')
