#!/usr/bin/env python3

# dhcpstats - A simple Flask API for querying ISC DHCP server information
#
#    Copyright (C) 2020 Joshua M. Boniface <joshua@boniface.me>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
###############################################################################

import os
import sys
import yaml
import re
import ipaddress
import flask
from functools import wraps
from flask_restful import Resource, Api, reqparse, abort
from time import time
from datetime import datetime

debug = True

def logger(msg, end='\n', t_start=None):
    # We only log in debug mode
    if not debug or not log_to_file:
        return 0

    # Starting a timed message
    if not t_start:
        t_start = int(time())
    # Completing a timed message
    else:
        t_tot = int(time()) - t_start
        msg = msg + " [{}s]".format(str(t_tot))
    # Output the message
    if debug:
        print(msg, end=end, file=sys.stderr)
    # Log the message
    if log_to_file and log_file:
        with open(log_file, 'a') as log_fh:
            log_fh.write('{} {}\n'.format(datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f'), msg))
    sys.stderr.flush()

    # Return t_start
    return t_start

config_file = os.environ.get('DHCPSTATS_CONFIG_FILE')
if config_file is None:
    logger('Error: The "DHCPSTATS_CONFIG_FILE" environment variable must be set before starting dhcpstats.')
    exit(1)
try:
    with open(config_file, 'r') as cfgfile:
        o_config = yaml.load(cfgfile, Loader=yaml.BaseLoader)
except Exception as e:
    logger('Error: Failed to parse configuration file: {}'.format(e))
    exit(1)
try:
    debug = o_config['dhcpstats'].get('debug', False)
    log_to_file = o_config['dhcpstats'].get('log_to_file', False)
    log_file = o_config['dhcpstats'].get('log_file', None)
    auth_string = o_config['dhcpstats'].get('auth_string', None)
    listen_addr = o_config['dhcpstats']['listen'].split(':')[0]
    listen_port = o_config['dhcpstats']['listen'].split(':')[-1]
    subnet_file = o_config['dhcpstats']['subnet_file']
    static_file = o_config['dhcpstats']['static_file']
    leases_file = o_config['dhcpstats']['leases_file']
except KeyError as e:
    logger('Error: Failed to parse required configuration key: {}'.format(e))
    exit(1)

if not debug:
    try:
        import gevent.pywsgi
        from gevent import monkey
    except:
        # Force running in Flask debug mode since there is no valid gevent
        debug = True

if log_to_file and log_file is not None:
    import logging
    logging.basicConfig(filename=log_file,level=logging.DEBUG)

# Set up the flask app
app = flask.Flask(__name__)

if debug:
    app.config['DEBUG'] = True

blueprint = flask.Blueprint('api', __name__, url_prefix='')

api = Api(blueprint)
app.register_blueprint(blueprint)

#
# Helper functions
#
def get_subnets(subnet_file, static_file, leases_file):
    """
    Parse the subnets file and leases file to obtain a list of subnets as well as the
    used and total number of IPs in the range.
    """
    # Read in the subnet_file
    t_start = logger('Reading subnet file... ', end='')
    with open(subnet_file, 'r') as subnets_fh:
        subnets_raw = subnets_fh.read().split('\n')
    logger('done.', t_start=t_start)

    t_start = logger('Parsing subnets... ', end='')
    subnets = dict()
    in_subnet_block = False
    in_pool_block = False
    current_subnet = ''

    # Iterate through the lines
    for line in subnets_raw:
        # Strip off any trailing semicolons
        line = re.sub(';$', '', line)
        # Split the line for easier parsing later
        line_split = line.split()
        # End of a subnet block
        if re.match('^}', line):
            in_subnet_block = False
            if current_subnet:
                subnets[current_subnet.with_prefixlen]['statics'] = dict()
                subnets[current_subnet.with_prefixlen]['leases'] = dict()
            continue
        # Inside a subnet block
        if in_subnet_block:
            # End of a pool block
            if re.match('^\s*}$', line):
                in_pool_block = False
            # Inside a pool block
            if in_pool_block:
                # A range line
                if re.match('^\s*range', line):
                    range_start = ipaddress.ip_address(re.sub(';', '', line_split[1]))
                    range_end = ipaddress.ip_address(re.sub(';', '', line_split[2]))
                    range_length = int(range_end) - int(range_start) + 1

                    subnets[current_subnet.with_prefixlen]['ranges'].append([str(range_start), str(range_end)])
                    subnets[current_subnet.with_prefixlen]['ips']['total'] += range_length
            # Start of a pool block
            if re.match('^\s*pool', line):
                in_pool_block = True

            # Description line (begins with '#$')
            if re.match('^\s*#\$', line):
                subnets[current_subnet.with_prefixlen]['description'] = ' '.join(line_split[1:])

            # Routers
            if re.match('^\s*option routers', line):
                subnets[current_subnet.with_prefixlen]['routers'] = line_split[-1].split(',')

            # DNS servers
            elif re.match('^\s*option domain-name-servers', line):
                subnets[current_subnet.with_prefixlen]['dns_servers'] = [ server for server in line_split[-1].split(',') ]
            # NTP servers
            elif re.match('^\s*option ntp-servers', line):
                subnets[current_subnet.with_prefixlen]['ntp_servers'] = [ server for server in line_split[-1].split(',') ]
            # Domain name
            elif re.match('^\s*option domain-name', line):
                subnets[current_subnet.with_prefixlen]['domain_name'] = re.sub('"', '', line_split[-1])

            # DDNS Domain name
            elif re.match('^\s*ddns-domainname', line):
                subnets[current_subnet.with_prefixlen]['ddns_domain_name'] = re.sub('"', '', line_split[-1])

            continue

        # Start of a subnet block
        if re.match('^subnet', line):
            in_subnet_block = True
            subnet = ipaddress.ip_network('{}/{}'.format(line_split[1], line_split[3]))
            current_subnet = subnet
            subnets[subnet.with_prefixlen] = dict()
            subnets[subnet.with_prefixlen]['ranges'] = []
            subnets[subnet.with_prefixlen]['ips'] = {}
            subnets[subnet.with_prefixlen]['ips']['total'] = 0
            subnets[subnet.with_prefixlen]['ips']['active'] = 0
            subnets[subnet.with_prefixlen]['ips']['free'] = 0
            subnets[subnet.with_prefixlen]['ips']['backup'] = 0
            subnets[subnet.with_prefixlen]['ips']['unused'] = 0
            subnets[subnet.with_prefixlen]['ips']['static'] = 0
    logger('done. ({} subnets parsed)'.format(len(subnets)), t_start=t_start)

    # Read in the static entries
    t_start = logger('Reading static file... ', end='')
    with open(static_file, 'r') as static_fh:
        statics_raw = static_fh.read().split('\n')
    logger('done.', t_start=t_start)

    t_start = logger('Parsing statics... ', end='')
    statics = dict()
    in_host_block = False
    current_static = ''

    # Iterate through the lines
    for line in statics_raw:
        # Split the line for easier parsing later
        line_split = line.split()
        # End of a host block
        if re.match('^}', line):
            in_host_block = False
            continue
        # Inside a host block (multiline)
        if in_host_block:
            if re.match('^\s*hardware ethernet', line):
                statics[current_static]['mac_address'] = re.sub(';', '', line_split[-1])
            elif re.match('^\s*fixed-address', line):
                statics[current_static]['ip_address'] = re.sub(';', '', line_split[-1])
            elif re.match('^\s*option host-name', line):
                statics[current_static]['host_name'] = re.sub('[";]', '', line_split[-1])
            continue
        # Start of a host block
        if re.match('^host', line):
            name = line_split[1]
            current_static = name
            # This is a single-line host entry, just do the rest of our parsing here
            if re.match('.*}$', line):
                in_host_section = False
                hardware_ethernet_idx = 0
                static_address_idx = 0
                host_name_idx = 0
                for idx, element in enumerate(line_split):
                    if re.match('}', element):
                        in_host_section = False
                        continue
                    if in_host_section:
                        if element == 'ethernet':
                            hardware_ethernet_idx = idx + 1
                        elif element == 'fixed-address':
                            static_address_idx = idx + 1
                        elif element == 'host-name':
                            host_name_idx = idx + 1
                        continue
                    if re.match('{', element):
                        in_host_section = True
                statics[name] = {}
                if hardware_ethernet_idx > 0:
                    statics[name]['mac_address'] = re.sub(';', '', line_split[hardware_ethernet_idx])
                if static_address_idx > 0:
                    statics[name]['ip_address'] = re.sub(';', '', line_split[static_address_idx])
                if host_name_idx > 0:
                    statics[name]['host_name'] = re.sub(';', '', line_split[host_name_idx])
            else:
                in_host_block = True
                statics[name] = {}
    logger('done. ({} statics parsed)'.format(len(statics)), t_start=t_start)

    # Read in the leases_file
    t_start = logger('Reading leases file... ', end='')
    with open(leases_file, 'r') as leases_fh:
        leases_raw = leases_fh.read().split('\n')
    logger('done.', t_start=t_start)

    t_start = logger('Parsing leases... ', end='')
    leases = dict()
    in_lease_block = False
    current_lease = ''

    lease_schema = {
        'starts': {   'data_start': 1, 'name_start': 0, 'name_end': 1 },
        'ends': {     'data_start': 1, 'name_start': 0, 'name_end': 1 },
        'tstp': {     'data_start': 1, 'name_start': 0, 'name_end': 1 },
        'tsfp': {     'data_start': 1, 'name_start': 0, 'name_end': 1 },
        'atsfp': {    'data_start': 1, 'name_start': 0, 'name_end': 1 },
        'cltt': {     'data_start': 1, 'name_start': 0, 'name_end': 1 },
        'binding': {  'data_start': 2, 'name_start': 0, 'name_end': 2 },
        'hardware': { 'data_start': 2, 'name_start': 0, 'name_end': 2 },
        'uid': {      'data_start': 1, 'name_start': 0, 'name_end': 1 },
        'set': {      'data_start': 3, 'name_start': 1, 'name_end': 2 }
    }

    # Iterate through the lines
    for line in leases_raw:
        # Split the line for easier parsing later
        line_split = line.split()
        # End of a lease block
        if re.match('^}', line):
            in_lease_block = False
            continue
        # Inside a lease block
        if in_lease_block:
            # Determine the type and thus data len
            field = line_split[0]
            if lease_schema.get(field):
                field_name = '-'.join(line_split[lease_schema[field]['name_start']:lease_schema[field]['name_end']])
                field_data = re.sub('[";]', '', ' '.join(line_split[lease_schema[field]['data_start']:]))
                leases[str(current_lease)][field_name] = field_data
            continue
        # Start of a lease block
        if re.match('^lease', line):
            in_lease_block = True
            lease = ipaddress.ip_address(line_split[1])
            current_lease = lease
            leases[str(lease)] = dict()
    logger('done. ({} leases parsed)'.format(len(leases)), t_start=t_start)

    # We now have a full dictionary of subnets and of leases; combine them into a final data structure
    t_start = logger('Combining and counting subnets... ', end='')
    for subnet in subnets:
        subnet_used = subnets[subnet]['ips']['active'] + subnets[subnet]['ips']['free'] + subnets[subnet]['ips']['backup']
        subnet_unused = subnets[subnet]['ips']['total'] - subnet_used
        subnets[subnet]['ips']['unused'] = subnet_unused
    logger('done.', t_start=t_start)

    t_start = logger('Combining and counting statics... ', end='')
    for static in statics:
        static_subnet = None
        static_ipobj = ipaddress.ip_address(statics[static]['ip_address'])
        for subnet in subnets:
            subnet_ipobj = ipaddress.ip_network(subnet)
            if static_ipobj in subnet_ipobj:
                static_subnet = subnet
        if static_subnet:
            subnets[static_subnet]['statics'][static] = statics[static]
            subnets[static_subnet]['ips']['static'] += 1
    logger('done.', t_start=t_start)

    t_start = logger('Combining and counting leases... ', end='')
    subnets_ipobj = list()
    for subnet in subnets.keys():
        subnets_ipobj.append(ipaddress.ip_network(subnet))
    for lease in leases:
        lease_subnet = None
        lease_ipobj = ipaddress.ip_address(lease)
        for subnet_ipobj in subnets_ipobj:
            if lease_ipobj in subnet_ipobj:
                lease_subnet = subnet_ipobj.with_prefixlen
                break
        if lease_subnet:
            lease_data = leases[lease]
            binding_state = lease_data['binding-state']
            if binding_state == 'active':
                subnets[lease_subnet]['ips']['active'] += 1
            elif binding_state == 'free':
                subnets[lease_subnet]['ips']['free'] += 1
            elif binding_state == 'backup':
                subnets[lease_subnet]['ips']['backup'] += 1
            subnets[lease_subnet]['leases'][lease] = lease_data
    logger('done.', t_start=t_start)

    retdata = subnets
    retcode = 200
    return retdata, retcode

#
# API helper definitons
#
def Authenticator(function):
    @wraps(function)
    def authenticate(*args, **kwargs):
        if auth_string is None:
            return function(*args, **kwargs)
        if 'X-Api-Key' in flask.request.headers:
            if flask.request.headers.get('X-Api-Key') == auth_string:
                return function(*args, **kwargs)
        return { "message": "X-Api-Key authentication failed." }, 401
    return authenticate

#
# API routes
#

class API_Root(Resource):
    @Authenticator
    def get(self):
        """
        Return basic details of the API
        ---
        tags:
          - root
        responses:
          200:
            description: OK
            schema:
              type: object
              id: API-Root
              properties:
                message:
                  type: string
                  description: A text message
                  example: "dhcpstats API"
        """
        return { "message": "dhcpstats API" }
api.add_resource(API_Root, '/')

class API_Subnets(Resource):
    @Authenticator
    def get(self):
        """
        Return a list of active subnets
        ---
        rags:
          - subnets
        responses:
          200:
            description: OK
            schema:
              type: object
              id: subnet
              properties:
        """
        return get_subnets(subnet_file, static_file, leases_file)
api.add_resource(API_Subnets, '/subnets')

#
# Entrypoint
#

if debug:
    app.run(listen_addr, listen_port)
else:
    monkey.patch_all()
    http_server = gevent.pywsgi.WSGIServer(
        (listen_addr, listen_port),
        app
    )
    http_server.serve_forever()
