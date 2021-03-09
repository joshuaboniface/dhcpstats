#!/usr/bin/env python3

# dhcpstats-combiner - Combine results from several dhcpstats instances consistently
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
import signal
import yaml
import json
import flask
import requests
from functools import wraps
from flask_restful import Resource, Api, reqparse, abort
from time import time
from datetime import datetime

debug = True

def logger(msg, end='\n', t_start=None):
    # We only log in debug mode
    if not debug and not log_to_file:
        return 0

    # Starting a timed message
    if not t_start:
        t_start = int(time())
        msg = '{} {}'.format(datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f'), msg)
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
    print('Error: The "DHCPSTATS_CONFIG_FILE" environment variable must be set before starting dhcpstats.')
    exit(1)
try:
    with open(config_file, 'r') as cfgfile:
        o_config = yaml.load(cfgfile, Loader=yaml.SafeLoader)
except Exception as e:
    print('Error: Failed to parse configuration file: {}'.format(e))
    exit(1)
try:
    debug = o_config['dhcpstats-combiner'].get('debug', False)
    log_to_file = o_config['dhcpstats-combiner'].get('log_to_file', False)
    log_file = o_config['dhcpstats-combiner'].get('log_file', None)
    auth_string = o_config['dhcpstats-combiner'].get('auth_string', None)
    listen_addr = o_config['dhcpstats-combiner']['listen'].split(':')[0]
    listen_port = int(o_config['dhcpstats-combiner']['listen'].split(':')[-1])
    host_list = o_config['dhcpstats-combiner']['hosts']
except KeyError as e:
    print('Error: Failed to parse required configuration key: {}'.format(e))
    exit(1)

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
def get_data(api_host, api_port, api_password, mode):
    logger("Querying host {}:{} mode {}".format(api_host, api_port, mode))
    api_headers = { 'X-Api-Key': api_password }
    api_url = "http://{}:{}/subnets/{}".format(api_host, api_port, mode)
    response = requests.get(api_url, headers=api_headers)
    if response.status_code == 200:
        return json.loads(response.content.decode('utf-8'))
    else:
        return None

def combine_data(split_data):
    combined_data = dict()

    # Phase 1: Determine any duplicated subnets between the instances
    all_keys = list()
    for instance in split_data:
        if instance is None:
            continue
        instance_keys = instance.keys()
        for key in instance_keys:
            all_keys.append(key)
    seen = set()
    duplicate_subnets = [ key for key in all_keys if key in seen or seen.add(key) ]

    # Phase 2: Check each subnet in each instance for the # of used IPs
    for subnet in duplicate_subnets:
        # Get a list if indexes and instances and the count of this subnet in all instances
        instance_list = list()
        for idx, instance in enumerate(split_data):
            if subnet in list(instance.keys()):
                instance_list.append(idx)
        count = len(instance_list)
        # If there is only a single instance, append the data to the output list
        if count == 1:
            combined_data[subnet] = split_data[instance_list[0]][subnet]
        # If there is more than one instance, do more parsing
        if count > 1:
            logger('Found dupe subnet {} in instances {}'.format(subnet, instance_list))
            combined_tmp = list()
            # Create a temporary list containing the dictionaries from all instances if they contain IP info
            for instance_idx in instance_list:
                if split_data[instance_idx][subnet].get('ips', None) is not None:
                    combined_tmp.append(split_data[instance_idx][subnet])
            # If there's only one "real" instance, add it
            if len(combined_tmp) == 1:
                combined_data[subnet] = combined_tmp[0]
                continue
            # For each instance, record the number of 'active' IPs for the subnet
            active_counts = list()
            for tmp in combined_tmp:
                active_counts.append(tmp['ips'].get('active', 0))
            # For each count, check if it's greater than 0, and append the data to the active subnets list
            active_subnets = list()
            for idx, count in enumerate(active_counts):
                if count > 0:
                    active_subnets.append(combined_tmp[idx])
            # If there is more than one active subnet, this is a true dupe between dhcpstats instances,
            # not some failover cluster configuration. We will append both but renaming the keys based
            # on the instance hostname so the final dict is valid
            if len(active_subnets) > 1:
                for instance_idx in instance_list:
                    combined_data['{} [{}]'.format(subnet, host_list[instance_idx]['hostname'])] = split_data[instance_idx][subnet]
            # If there is less than one active subnet, just use the first (the data is zero anyways)
            elif len(active_subnets) < 1:
                combined_data[subnet] = split_data[0][subnet]
            # Use the single active instance
            else:
                combined_data[subnet] = tmp

    return combined_data

def query_hosts(hosts, mode):
    data = []
    formatted_data = {}

    if mode in ['all', 'list']:
        for host in hosts:
            data.append(get_data(host['hostname'], host['port'], host['api_password'], mode))
        formatted_data = combine_data(data)
    else:
        for host in hosts:
            data_tmp = get_data(host['hostname'], host['port'], host['api_password'], mode)
            if data_tmp.get('ips', None) is not None:
                if data_tmp['ips'].get('active', 0) > 0:
                    formatted_data = data_tmp
                    break

    return True, formatted_data

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
        return { "message": "dhcpstats API" }, 200
api.add_resource(API_Root, '/')

class API_Subnets(Resource):
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
        return { "message": "dhcpstats API" }, 200
api.add_resource(API_Subnets, '/subnets')

class API_Subnets_All(Resource):
    @Authenticator
    def get(self):
        """
        Return a list of active subnets with all lease data
        ---
        tags:
          - subnets
        responses:
          200:
            description: OK
            schema:
              type: object
              id: subnet
              properties:
        """
        result, data = query_hosts(host_list, 'all')
        if result:
            return data, 200
        else:
            return { "result": data }, 500
api.add_resource(API_Subnets_All, '/subnets/all')

class API_Subnets_List(Resource):
    @Authenticator
    def get(self):
        """
        Return list of active subnets
        ---
        tags:
          - subnets
        responses:
          200:
            description: OK
            schema:
              type: object
              id: subnet
              properties:
        """
        result, data = query_hosts(host_list, 'list')
        if result:
            for subnet in data:
                if data[subnet].get('leases', None) is not None:
                    del data[subnet]['leases']
                if data[subnet].get('statics', None) is not None:
                    del data[subnet]['statics']
            return data, 200
        else:
            return { "result": data }, 500
api.add_resource(API_Subnets_List, '/subnets/list')

class API_Subnets_Detail(Resource):
    @Authenticator
    def get(self, subnet_ip):
        """
        Return full details, including leases and statics, of a given subnet
        ---
        tags:
          - subnets
        responses:
          200:
            description: OK
            schema:
              type: object
              id: subnet
              properties:
        """
        result, data = query_hosts(host_list, subnet_ip)
        if result:
            return data, 200
        else:
            return { "result": data['result'] }, 500
api.add_resource(API_Subnets_Detail, '/subnets/<subnet_ip>')

#
# Entrypoint
#

if __name__ == "__main__":
    logger('Starting up')

    # Set up clean termination
    def cleanup(signum='', frame=''):
        exit(0)
    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGQUIT, cleanup)
    signal.signal(signal.SIGHUP, cleanup)

    if debug:
        logger('Starting API in debug mode')
        app.run(listen_addr, listen_port, use_reloader=True, threaded=True)
    else:
        logger('Starting API in production mode')
        app.run(listen_addr, listen_port, use_reloader=False, threaded=True)
