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
from queue import Queue
from threading import Thread

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
    auth_strings = o_config['dhcpstats-combiner'].get('auth_strings', None)
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
def get_data(queue, api_host, api_port, api_password, mode, host_idx, hosts_count):
    logger("Querying host {}:{} mode {} [{}/{}]".format(api_host, api_port, mode, host_idx, hosts_count))
    api_headers = { 'X-Api-Key': api_password }
    api_url = "http://{}:{}/subnets/{}".format(api_host, api_port, mode)
    try:
        response = requests.get(api_url, headers=api_headers)
    except requests.exceptions.ConnectionError:
        data = None

    if response.status_code == 200:
        data = json.loads(response.content.decode('utf-8'))
    else:
        data = None

    if data is None:
        logger("Got no valid data from host {}:{} [{}/{}]".format(api_host, api_port, host_idx, hosts_count))
    else:
        logger("Got data from host {}:{} [{}/{}]".format(api_host, api_port, host_idx, hosts_count))

    queue.put(data)

    return

def combine_data(split_data):
    combined_data = dict()
    duplicate_subnets = list()

    # Phase 0: Prepare an instance list by index
    instance_name_list = list()
    for idx, instance in enumerate(split_data):
        instance_name_list.append(host_list[idx]['hostname'])
    instance_count = len(instance_name_list)

    # Phase 1: Determine any duplicated subnets between the instances
    all_keys = list()
    for instance in split_data:
        if instance is None:
            continue
        instance_keys = instance.keys()
        if instance_keys is None:
            continue
        for key in instance_keys:
            all_keys.append(key)
    dupe = set()
    for key in all_keys:
        if key in dupe and key not in duplicate_subnets:
            duplicate_subnets.append(key)
        else:
            dupe.add(key)
    for instance in split_data:
        try:
            for key in instance.keys():
                if key not in duplicate_subnets:
                    combined_data[key] = instance[key]
        except AttributeError as e:
            logger("Failed to parse {}: {}".format(instance, e))

    # Phase 2: Check each subnet in each instance for the # of used IPs
    for subnet in duplicate_subnets:
        logger("Parsing dupe'd subnet {}".format(subnet))
        temp_data = dict()

        # Get a dictionary with all the various iterations of this subnet in it
        for instance_idx, instance_name in enumerate(instance_name_list):
            try:
                temp_data[instance_name] = split_data[instance_idx][subnet]
            except KeyError:
                # This subnet isn't in this instance, so continue
                continue

        # Parse through the list and remove any obviously-useless subnet instances
        first_zeroactive = None
        first_zerototal = None
        for instance_name in temp_data.copy():
            # Remove entries which don't interest us
            if not temp_data[instance_name].get('monitor', False):
                # We should not monitor this subnet on this instance
                del temp_data[instance_name]
            elif not temp_data[instance_name].get('ips', False):
                # The subnet 'ips' entry is empty
                del temp_data[instance_name]
            elif temp_data[instance_name]['ips'].get('total', 0) < 1:
                # There are zero configured IPs in this subnet on this instance
                # We should save a copy though, just in case we end up with no entries for the subnet
                if first_zerototal is None:
                    first_zerototal = temp_data[instance_name]
                del temp_data[instance_name]
            elif temp_data[instance_name]['ips'].get('active', 0) < 1:
                # There are zero active IPs in this subnet on this instance
                # We should save a copy though, just in case we end up with no entries for the subnet
                if first_zeroactive is None:
                    first_zeroactive = temp_data[instance_name]
                del temp_data[instance_name]

        # Check the result of the previous work to see how many subnet definitions we have left
        if temp_data is None or len(temp_data) < 1:
            # There are none left, so there were dupes but none of them had any valid IPs. Use the first_zeroactive data
            if first_zeroactive is not None:
                combined_data[subnet] = first_zeroactive
            elif first_zerototal is not None:
                combined_data[subnet] = first_zerototal
            else:
                combined_data[subnet] = dict()
        elif len(temp_data) > 1:
            # Somehow there are still multiple instances. We must look through those that remain and show only the one with the most active
            max_active_count = 0
            max_active_idx = 0
            for idx, instance_name in enumerate(temp_data.copy()):
                active_count = temp_data[instance_name]['ips']['active']
                if active_count > max_active_count:
                    max_active_count = active_count
                    max_active_ifx = idx
            key = list(temp_data.keys())[max_active_idx]
            combined_data[subnet] = temp_data[key]
        else:
            key = list(temp_data.keys())[0]
            # We have exactly one subnet left, so that must be the good one
            combined_data[subnet] = temp_data[key]

    return combined_data

def query_hosts(hosts, mode):
    data = list()
    formatted_data = dict()
    host_queues = dict()
    host_threads = dict()

    if mode in ['all', 'list']:
        hosts_count = len(hosts)
        logger("Acquiring data from {} hosts".format(hosts_count))
        for host_idx, host in enumerate(hosts, start=1):
            hostname = host['hostname']
            host_queues[hostname] = Queue()
            host_threads[hostname] = Thread(target=get_data, args=(host_queues[hostname], host['hostname'], host['port'], host['api_password'], mode, host_idx, hosts_count), kwargs={})
            host_threads[hostname].start()
        for host_idx, host in enumerate(hosts, start=1):
            hostname = host['hostname']
            logger("Joining gathering thread for host {} [{}/{}]".format(hostname, host_idx, hosts_count))
            host_threads[hostname].join(timeout=15.0)
        for host_idx, host in enumerate(hosts, start=1):
            try:
                hostname = host['hostname']
                logger("Appending queue data for host {} [{}/{}]".format(hostname, host_idx, hosts_count))
                queue_data = host_queues[hostname].get(block=False)
                data.append(queue_data)
            except Exception as e:
                logger("ERROR: {}".format(e))

        logger("Parsing data from {} hosts".format(hosts_count))
        formatted_data = combine_data(data)

    else:
        hosts_count = len(hosts)
        logger("Acquiring data from {} hosts".format(hosts_count))
        for host_idx, host in enumerate(hosts, start=1):
            hostname = host['hostname']
            host_queues[hostname] = Queue()
            host_threads[hostname] = Thread(target=get_data, args=(host_queues[hostname], host['hostname'], host['port'], host['api_password'], mode, host_idx, hosts_count), kwargs={})
            host_threads[hostname].start()
        for host_idx, host in enumerate(hosts, start=1):
            hostname = host['hostname']
            logger("Joining gathering thread for host {} [{}/{}]".format(hostname, host_idx, hosts_count))
            host_threads[hostname].join(timeout=15.0)
        logger("Parsing data from {} hosts".format(hosts_count))
        for host in hosts:
            hostname = host['hostname']
            data_tmp = host_queues[hostname].get()
            if type(data_tmp) is not dict:
                continue
            if data_tmp.get('ips', None) is not None:
                if data_tmp['ips'].get('active', 0) > 0:
                    formatted_data = data_tmp
                    break
            # If all returned no active IPs, use the last (all the same)
            formatted_data = data_tmp

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
            if auth_string is not None:
                if flask.request.headers.get('X-Api-Key') == auth_string:
                    return function(*args, **kwargs)
            if auth_strings is not None:
                for string in auth_strings:
                    if flask.request.headers.get('X-Api-Key') == string:
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
        logger('Terminating on signal {}'.format(signum))
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
