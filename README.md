# DHCPStats

DHCPStats is a Python 3 Flask-based API to obtain active stats about the subnets, static reservations, and active leases of an ISC-DHCP (dhcpd) server.

While there are several ways to get this information, for instance `dhcp-lease-list` or OMAPI, both options have drawbacks. `dhcp-lease-list` provides human-readable output which makes it harder to use programmatically, and only provides lease information, nothing else. OMAPI is hard-to-use and has some strange conventions, as well as being a configuration setter making it easy to mess up.

DHCPStats seeks to make life a little easier. It provides a convenient HTTP API returning JSON representations of the subnets in your configuration, with all the important subnet details, as well as lists both of all static reservations defined in the configuration for the subnet, as well as all active leases for the subnet. This provides a great deal of flexibility to the consumer, allowing them to decide how to use the structured data to build monitoring or observation tools to provide insight into their DHCP server.

## Usage

1. Install the required Python 3 dependencies: `yaml`, `apscheduler`, `flask`, `flask_restful`, `gevent`, and `functools`.

1. Install the `dhcpstats.py` binary somewhere useful, for instance in `/usr/local/bin`.

1. Copy the configuration file `dhcpstats.yml` to somewhere useful, for instance in `/etc/dhcp/dhcpstats.yml`. Edit it to suit your needs - configuration detail are provided in the next section.

1. Run the API using a service manager of your choice; a simple SystemD unit, a SysV initscript, and a FreeBSD rc.d initscript are provided. Make sure you export the `DHCPSTATS_CONFIG_FILE` environment variable containing the location of the configuration in the previous step.

1. Query the API endpoints to get the information, and use it as you wish.

1. For production deployments, put the API behind a reverse proxy (e.g. NGiNX) with ACLs for maximum security.

### Specific Details

#### Debian

* Use the SystemD or SysV initscript to start DHCPStats.
* For SysV init, the `/etc/default/dhcpstats` file should be created in order to export the `DHCPSTATS_CONFIG_FILE`.
* For SystemD, the service unit should be edited to set the location of the `DHCPSTATS_CONFIG_FILE`.
* DHCPStats has the following dependencies: `python3-yaml` `python3-gevent` `python3-flask` `python3-flask-restful` `python3-apscheduler`

#### FreeBSD (12+)

* FreeBSD does not support `/usr/bin/env X` shebang constructs, so this must be replaced with the abolute path to your `python3` binary in `dhcpstats.py`.
* The configuration file is set in `/etc/rc.conf` with the `dhcpstats_config` argument. Like all FreeBSD daemons, `dhcpstats_enable` must be set to `YES` as well.
* DHCPStats has the following dependencies: `py37-yaml` `py37-gevent` `py37-flask` `py37-flask-restful` `py37-apscheduler`

## Configuration File

DHCPStats is configured with a basic YAML-formatted configuration file. The example contains some testing values as well as comments, but this section details them. All configuration is located under a single `dhcpstats:` root key.

#### `debug`

The `debug` option can be either `true` or `false`. When `true`, it enables the debug Flask web server and debug mode within Flask. When `false`, the Flask app runs under the GEvent PyWSGI web server. If this option is absent, it is assumed as `false`.

#### `log_to_file`

The `log_to_file` option can be either `true` or `false`. When `true`, log output of the daemon to the file specified in `log_file`. If this option is absent, it is assumed as `false`.

#### `log_file`

The `log_file` option sets the path to a log file when `log_to_file` is `true`. If this option is absent, file logging is disabled implicitly.

#### `data_directory`

The `data_directory` option sets the directory path for dhcpstats to store its parsed information in JSON format. This enables quicker responses by only parsing the data sparingly, and then storing it in this directory for future use.

#### `auto_refresh`

The `auto_refresh` option can be wither `true` or `false`. When `true`, the API will occasionally refresh the parsed data stored under `data_directory` automatically. When `false`, a specific API endpoint must be hit to refresh the data. In either case, the data is refreshed once at startup.

#### `refresh_time`

The `refresh_time` option specifies the number of seconds between `auto_refresh` events. This number should be high enough to avoid overloading the system (dependent on parsing time) while low enough to not return excessively-outdated data. Between 30 and 300 seconds generally sufficient.

#### `listen`

The `listen` option contains an `<ipaddress>:<port>` string which tells the Flask server where to listen. You can choose any IP on the host and any port; use `0.0.0.0` for the IP to listen on all interfaces.

#### `auth_string`

The `auth_string` option provides a password which can be used to control access to the API if it is listening on a public/Internet-facing IP address directly. If this option is present, the client must send this string in an `X-Api-Key` header to be authenticated. If this option is absent, there is no authentication.

#### `subnet_file`

The `subnet_file` option sets a path to the ISC-DHCP configuration file which lists all subnets your DHCP server provides services for. In simple deployments, this is likely to be `/etc/dhcp/dhcpd.conf` or something similar; in more advanced deployments with split configuration files, it must be a *single* file containing all subnets; DHCPStats cannot parse subnet definitions from multiple files.

#### `static_file`

The `static_file` option sets a path to the ISC-DHCP configuration file which lists all static IP reservations for your DHCP server. Like `subnet_file`, this may be the main `dhcpd.conf` file, or a single separate file.

#### `leases_file`

The `leases_file` option sets a path to the ISC-DHCP live leases database. This is usually called `dhcpd.leases` at `/var/lib/dhcp/dhcpd.leases` or `/var/db/dhcp/dhcpd.leases`, depending on your operating system.

## API Usage

The API provides five endpoints:

#### `/`

The root endpoint returns status information about the API.

#### `/subnets`

The `/subnets` endpoint returns status information about the API.

#### `/subnets/list`

The `/subnets/list` endpoint returns a list of found subnets and their details. The subsections `statics` and `leases` are not present in this output to minimize its size.

#### `/subnets/all`

The `/subnets/all` endpoint returns a list of found subnets and their details, identical to the `/subnets/list` endpoint, but including all `statics` and `leases` information for each subnet.

WARNING: This output can be very large on larger ISC-DHCP instances.

#### `/subnets/<subnet_ip>`

The `/subnets/<subnet_ip>` endpoint returns the subnet details for the `<subnet_ip>` subnet.

Due to the limitations of HTTP, the subnet mask component of a full subnet address (e.g. `10.0.0.0/24`) cannot be sent. Thus, this endpoint expects **only** the network address component of the subnet (e.g. `10.0.0.0`) without the mask component. In normal networking situations this would be ambiguous, but since the API already contains a full list of the valid subnets, at most one subnet will exactly match this network address in a properly-configured ISC-DHCP server, and that subnet only will be returned. Sending a mask will result in a 404 error; when for instance taking output from the `/subnets/list` output, care should be taken to strip off the subnet mask portion before sending the reuest for full details.

## Example Output

### Full subnet output

This is an example of the output for a simple subnet with a few reservations and active leases. Your real-world subnets will likely have many more `leases` entries than shown here, but these examples should give a good idea of the data that will be returned.

The schema is flexible. If some elements of a given entry are not found (for instance, you had no `ntp-servers` configured for a subnet, or a `leases` entry had no `ddns-fwd-name` entry), they will be ommitted entirely. The API client must handle this gracefully and never implicitly assume that any uncommon value will be present.

```
{
  "10.0.0.0/24": {
    "ranges": [
      [
        "10.0.0.100",
        "10.0.0.149"
      ]
    ],
    "ips": {
      "total": 50,
      "active": 2,
      "free": 2,
      "backup": 0,
      "unused": 46
    },
    "dns_servers": [
      "10.0.0.2",
      "10.0.0.3"
    ],
    "routers": [
      "10.0.0.1"
    ],
    "domain_name": "subnet.domain.tld",
    "ddns_domain_name": "subnet.domain.tld",
    "ntp_servers": [
      "10.0.0.2",
      "10.0.0.3"
    ],
    "statics": {
      "server1": {
        "mac_address": "52:54:00:ff:ff:f0",
        "ip_address": "10.0.0.11",
        "host_name": "server1"
      },
      "server2": {
        "mac_address": "52:54:00:ff:ff:f1",
        "ip_address": "10.0.0.12",
        "host_name": "server2"
      }
    },
    "leases": {
      "10.0.0.120": {
        "starts": "4 2020/08/06 02:28:52",
        "ends": "4 2020/08/06 06:28:52",
        "tstp": "4 2020/08/06 06:28:52",
        "tsfp": "4 2020/08/13 04:28:52",
        "atsfp": "4 2020/08/13 04:28:52",
        "cltt": "4 2020/08/06 02:28:52",
        "binding-state": "free",
        "hardware-ethernet": "52:54:00:ff:02:21",
        "uid": "\\377\\000\\377\\002!\\000\\001\\000\\001&\\276'cRT\\000\\377\\002!"
      },
      "10.0.0.125": {
        "starts": "4 2020/08/06 02:29:03",
        "ends": "4 2020/08/06 06:29:03",
        "tstp": "4 2020/08/06 06:29:03",
        "tsfp": "4 2020/08/13 04:29:03",
        "atsfp": "4 2020/08/13 04:29:03",
        "cltt": "4 2020/08/06 02:29:03",
        "binding-state": "free",
        "hardware-ethernet": "52:54:00:1a:ce:31",
        "uid": "\\377\\000\\032\\3161\\000\\001\\000\\001&\\276'jRT\\000\\032\\3161"
      },
      "10.0.0.131": {
        "starts": "3 2020/09/16 14:41:51",
        "ends": "3 2020/09/23 14:41:51",
        "tstp": "0 2020/09/27 02:41:51",
        "tsfp": "0 2020/09/27 02:41:51",
        "atsfp": "0 2020/09/27 02:41:51",
        "cltt": "3 2020/09/16 14:41:51",
        "binding-state": "active",
        "hardware-ethernet": "52:54:00:16:7d:92",
        "ddns-fwd-name": "clientA.subnet.domain.tld",
        "ddns-dhcid": "\\001\\002\\005v\\304\\013C1\\2468\\005?\\305W\\222\\331\\362\\324u\\240\\260\\244}\\235\\266\\226\\096\\221\\360\\355\\275\\002\\323,+",
        "ddns-rev-name": "131.0.101.10.in-addr.arpa."
      },
      "10.0.0.135": {
        "starts": "4 2020/09/17 01:00:24",
        "ends": "4 2020/09/24 01:00:24",
        "tstp": "3 2020/09/02 05:49:04",
        "tsfp": "0 2020/09/27 13:00:24",
        "atsfp": "0 2020/09/27 13:00:24",
        "cltt": "6 2020/08/15 16:03:45",
        "binding-state": "active",
        "hardware-ethernet": "52:54:00:10:5b:21",
        "uid": "\\377\\000\\020[!\\000\\031\\000\\031${F~RT\\001\\029[!"
      }
    }
  }
}
```

### Explanation of `ips`

The `ips` section of the subnet output contains information on the number of available IPs, the number of leases in various `binding-state`s, and the number of static leases. For example:

```
"ips": {
  "total": 150,
  "active": 64,
  "free": 41,
  "backup": 45,
  "unused": 0,
  "static": 34
}
```

The `total` value is calculated by examining all `ranges` entries inclusive. Thus, the range `10.0.0.100 - 10.0.0.149` would contain 50 `total` IPs. If there are multiple `ranges` entries, they are added together to determine the `total`.

The `active` value counts how many valid leases from the `dhcpd.leases` database are in an `active` `binding-state`. These are leases that are currently valid and assigned to a DHCP client.

The `free` value counts how many leases from the `dhcpd.leases` database are in a `free` `binding-state`. Once an `active` lease expires, the lease becomes `free` and is still stored in the database, where it can be claimed by another client in the future.

The `backup` value is only relevant for failover configurations. It counts the number of leases which are in a `backup` `binding-state`. These leases are reserved for DHCP failover and are thus not used by clients unless the server goes into a failover state.

The `unused` value is calculated by adding all the `active`, `free`, and `backup` counts together, then subtracting this from the `total` value. This value represents all the potentially valid leases the server could hand out from the configured `ranges`, but which have not been registered in the `dhcpd.leases` database yet due to not having ever been requested. After a long time of serving clients, it's unlikely that a subnet will have any `unused` IPs, but newer or low-volume subnets might have quite a lot of `unused` IPs.

The `static` value is calculated by examining all `statics` entries. Since static DHCP reservations in ISC-DHCP must be outside of the `ranges` to operate properly, this number has no relation to the remaining values, but is provided for convenience; it could easily be obtained by the client by counting the number of entries in the `statics` dictionary.

## Combiner

The `dhcpstats-combiner` tool acts as a client for `dhcpstats`, and a server for an upstream consumer. It can be used in situations where you might have multiple DHCPStats instances (for example, two or more DHCP servers) and want unified information from them.
