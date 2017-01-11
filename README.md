Cisco ISE
=========

This role manipulates Cisco Identity Services Engine configurations. <br />
Endpoint and Networkdevice manipulation (add, delete, change) are supported so far. 

Requirements
------------
Cisco ISE version 2.1 or 2.2

Prerequisites
-------------
External RESTful Service API must be enabled: <br />
http://www.cisco.com/c/en/us/td/docs/security/ise/2-1/api_ref_guide/api_ref_book/ise_api_ref_ers2.html#37305 <br />
The variables 'cisco_ise_ers_[variable]' must be set overridden to match your credentials.

Endpoint Manipulation
--------------
The play 'cisco_ise_endpoint' adds/changes or deletes MAC Addresses per Cisco ISE identitygroup. <br />
All given MAC Addresses for an identitygroup will be configured on ISE. All other MAC Addresses for this group will be deleted. <br /><br />
The module uses bulk API requests for adding and deleting endpoints for better performance. <br />
It should be able to handle <b>thousands</b> of MAC addresses. <br />
At the current version 'staticGroupAssignment' is always set to true, and staticProfileAssignment is always set to false. <br />
If MAC is an empty array and 'cisco_ise_endpoint_force: true' all Endpoints will be deleted! <br />
If MAC is an empty array and 'cisco_ise_endpoint_force: false' an error is raised. 


Networkdevice Manipulation
----------------
The play 'cisco_ise_networkdevice' adds/changes or deletes Networkdevices. <br />
Networkdevices are defined in the List: 'cisco_mgmt_devices'. The variables defaults are set  in 'cisco_mgmt_device_defaults'. Each of this variables can be overriden in 'cisco_mgmt_devices' per device. <br />


Role Variables
--------------
```
cisco_ise_ers_username: api
cisco_ise_ers_password: changeme

cisco_ise_ers_ssl: true
cisco_ise_ers_port: 9060
cisco_ise_ers_validate_certs: false

# if true and no mac address given to identity group
# all endpoints will be deleted 
cisco_ise_endpoint_force: true
# how long do we wait for bulk jobs to be completed
cisco_ise_endpoint_timeout: 30

#
# identitygroups are defined as ARRAYS. 
# each ARRAY holds a DICT with keys: 'name' and 'mac' 
# if MAC is empty array and 'cisco_ise_endpoint_force: true' 
# all Endpoints will be deleted!
#
cisco_ise_identitygroups: [ {
	name: "Workstation", 
	mac: ["00:16:3e:2b:46:35","00:16:3e:5e:ab:2e","00:16:3e:7d:26:5a"] },{
	name: "Blacklist",
	mac: ["00:16:3e:2b:46:38"]
} ]

# if true all devices will be deleted and created again
# use this if only RADIUS or TACACS shared secrets changed
cisco_ise_networkdevice_force: false

#
# networkdevice configuration 
# splitted into default and device values
# snmp_v3_security_level: can be either AUTH, NO_AUTH, PRIV
# tacacs_connection_mode: one out of ["OFF", ON_DRAFT_COMPLIANT, ON_LEGACY]
#
cisco_mgmt_device_defaults: {
  snmp_enabled: true,
  snmp_version: 2c,
  snmp_polling_interval: "28800",
  snmp_ro_community: public,
  snmp_rw_community: private,
  snmp_v3_username: snmpv3user,
  snmp_v3_auth_protocol: MD5,
  snmp_v3_auth_password: changeme,
  snmp_v3_privacy_protocol: DES,
  snmp_v3_privacy_password: changeme,
# AUTH, NO_AUTH, PRIV
  snmp_v3_security_level: AUTH,
  tacacs_enabled: false,
  tacacs_shared_secret: changeme,
# "OFF", ON_DRAFT_COMPLIANT, ON_LEGACY
  tacacs_connection_mode: "OFF",
  radius_enabled: false,
  radius_shared_secret: changeme,
  radius_enable_keywrap: false,
  radius_coaport: "1700",
  profile_name: Cisco,
  network_device_groups: ["Location#All Locations","Device Type#All Device Types"]
}

#
# this is how networkdevices are added
# MUST contain 'name' and 'ipaddress'
# CAN override any parameter from 'cisco_mgmt_device_defaults'
#
cisco_mgmt_devices: [ {
  name: testdevice1,
  ipaddress: 192.168.0.1 },{
  name: testdevice2,
  ipaddress: 192.168.0.2 }
]
```

Example Playbook
--------------
The playbook must contain 'gather_facts: False' and 'connection: local'<br />
Example:

```
- name: ISE
  hosts: ise  
  gather_facts: False
  connection: local
  roles: 
    - cisco_ise
  tags: 
    - ise  
```

License
-------

MIT

Author Information
------------------

Markus Rainer (maxrainer18@gmail.com)
