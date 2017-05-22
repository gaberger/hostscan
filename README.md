# README

This is a simple script that performs an nmap scan on a destination address, parses the XML result into a Python Map and can transform the data for use in creating host files, Ansible host manifests or drive an inventory database using MongoDB.


We leverage DocOpt for command processing:


```
Usage: nmap-scan [options] <network>

Options:
    --mongo-host MONGO_HOST                Mongo Host(default: localhost)
    --mongo-port MONGO_PORT                Mongo Port(default: 3001)
    --database DB                          Add records to mongo db
    --collection COLLECTION                Add records to mongo collection
    -H, --hosts                            Print *nix hosts file format [default].
    -R, --raw                              Print raw collection database
    -I, --insert                           Performs insert instead of in place update
    -S, --snmp                             Make SNMP calls
    -A, --ansible                          Make Ansible inventory
    -D, --debug                            Print debug information

```


As an example to run a scan on a 24bit subnet you could run:
```
nmap-scan.py -H 192.168.1.0/24
```

```
192.168.1.124	192-168-1-124
192.168.1.113	192-168-1-113
192.168.1.10	takagi
192.168.1.1	192-168-1-1
192.168.1.101	192-168-1-101
192.168.1.100	192-168-1-100
192.168.1.168	192-168-1-168
192.168.1.149	192-168-1-149
192.168.1.115	192-168-1-115
192.168.1.227	192-168-1-227
192.168.1.209	192-168-1-209
192.168.1.217	192-168-1-217
```

Generate an Ansible hosts file

```
[hosts]
192-168-1-10	ansible_ssh_user=root	ansible_ssh_pass=#password#
192-168-1-1	ansible_ssh_user=root	ansible_ssh_pass=#password#
192-168-1-101	ansible_ssh_user=root	ansible_ssh_pass=#password#
192-168-1-113	ansible_ssh_user=root	ansible_ssh_pass=#password#
192-168-1-168	ansible_ssh_user=root	ansible_ssh_pass=#password#
192-168-1-149	ansible_ssh_user=root	ansible_ssh_pass=#password#
192-168-1-115	ansible_ssh_user=root	ansible_ssh_pass=#password#
192-168-1-227	ansible_ssh_user=root	ansible_ssh_pass=#password#
192-168-1-209	ansible_ssh_user=root	ansible_ssh_pass=#password#
192-168-1-217	ansible_ssh_user=root	ansible_ssh_pass=#password#
```


More detail nmap scan:

```
 '192-168-1-115': {'_id': '192-168-1-115',
                   'ip': '192.168.1.115',
                   'mac': None,
                   'name': '192-168-1-115',
                   'services': [{'portid': '80',
                                 'product': 'HP Photosmart 7510 series printer http config',
                                 'protocol': 'tcp',
                                 'service_name': 'http'},
                                {'portid': '139',
                                 'product': None,
                                 'protocol': 'tcp',
                                 'service_name': 'netbios-ssn'},
                                {'portid': '443',
                                 'product': 'HP Photosmart 7510 series printer http config',
                                 'protocol': 'tcp',
                                 'service_name': 'http',
                                 'ssl_cn': None,
                                 'ssl_orgname': None,
                                 'ssl_valid': None}],
                   'vendor': None},
 '192-168-1-124': {'_id': '192-168-1-124',
                   'ip': '192.168.1.124',
                   'mac': None,
                   'name': '192-168-1-124',
                   'vendor': None},
 '192-168-1-149': {'_id': '192-168-1-149',
                   'ip': '192.168.1.149',
                   'mac': None,
                   'name': '192-168-1-149',
                   'vendor': None},
 '192-168-1-168': {'_id': '192-168-1-168',
                   'ip': '192.168.1.168',
                   'mac': None,
                   'name': '192-168-1-168',
                   'services': [{'portid': '111',
                                 'product': None,
                                 'protocol': 'tcp',
                                 'service_name': 'rpcbind'}],
                   'vendor': None},
 '192-168-1-209': {'_id': '192-168-1-209',
                   'ip': '192.168.1.209',
                   'mac': None,
                   'name': '192-168-1-209',
                   'services': [{'portid': '111',
                                 'product': None,
                                 'protocol': 'tcp',
                                 'service_name': 'rpcbind'}],
                   'vendor': None},
 '192-168-1-217': {'_id': '192-168-1-217',
                   'ip': '192.168.1.217',
                   'mac': None,
                   'name': '192-168-1-217',
                   'vendor': None},
 '192-168-1-227': {'_id': '192-168-1-227',
                   'ip': '192.168.1.227',
                   'mac': None,
                   'name': '192-168-1-227',
                   'vendor': None}}
```