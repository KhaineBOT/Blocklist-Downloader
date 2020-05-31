Blocklist-Downloader
====================

A python script to download ip blacklists and load them into a firewall (currently only pf and firewalld), unbound, squid, and bro

## Usage ##
-l / --location location to store blocklists 

-n / --blocklist_names specify names of blocklists to download

-o / --output specify the output format. currently supported are formats for pf, firewalld, squid, unbound, bro and csv

--list will list all of the supported blocklists

## Defaults ##
firewall = 'pf'

listType = 'ip'

location = '/root/tables/'

## Misc ##
Please contact me with any suggestions or improvements.  I've made this for my own use, but thought others could benefit from it
