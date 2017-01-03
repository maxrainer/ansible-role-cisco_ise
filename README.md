Cisco ISE
=========

This role helps to manipulate Cisco Identity Services Engine configurations.<br />
At the moment only Endpoint configuration is supported.


Requirements
------------
Cisco ISE 2.1 or 2.2


Prerequisites
-------------
External RESTful Service API must be enabled: <br />
http://www.cisco.com/c/en/us/td/docs/security/ise/2-1/api_ref_guide/api_ref_book/ise_api_ref_ers2.html#37305

Endpoint Manipulation
--------------
The play 'cisco_ise_endpoint' adds/changes or deletes MAC Addresses per Cisco ISE identitygroup. <br />
All given MAC Addresses for an identitygroup will be configured on ISE. All other MAC Addresses for this group will be deleted. <br /><br />
The module uses bulk API requests for adding and deleting endpoints for better performance. <br />
It should be able to handle thousands of MAC addresses. <br />
At the current version 'staticGroupAssignment' is always set to true, and staticProfileAssignment is always set to false. <br />
If MAC is an empty array and 'cisco_ise_endpoint_force: true' all Endpoints will be deleted! <br />
If MAC is an empty array and 'cisco_ise_endpoint_force: false' an error is raised. 

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
