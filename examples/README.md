# Examples

This directory provides example clients for the DHCPStats API.

## dhcpstats.cmk

This is a Check MK agent `local` script which will provide a check for each subnet, showing the `active` leases versus the `total` leases, as well as a percentage value for long-term perfdata tracking. The default warning and critical thresholds are hardcoded to 90% and 95%, respectively.
