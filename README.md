Cisco ISE
=========

This role helps to manipulate Cisco Identity Services Engine configurations.<br />
At the moment only Endpoint configuration is supported.


Requirements
------------
Cisco ISE 2.1 or 2.2


Prerequisites
-------------
External RESTful Service API must be enabled: 
http://www.cisco.com/c/en/us/td/docs/security/ise/2-1/api_ref_guide/api_ref_book/ise_api_ref_ers2.html#37305

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

# this is how identitygroups must be defined
# variable takes a list of hashes (keys are 'name' and 'macaddress')
cisco_ise_identitygroups: [{
	name: "Workstation", 
	macaddress: ["00:16:3e:2b:46:35","00:16:3e:5e:ab:2e","00:16:3e:7d:26:5a"] },{
	name: "Blacklist",
	macaddress: [] }
]
```

Dependencies
------------

A list of other roles hosted on Galaxy should go here, plus any details in regards to parameters that may need to be set for other roles, or variables that are used from other roles.

Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts: servers
      roles:
         - { role: username.rolename, x: 42 }

License
-------

MIT

Author Information
------------------

Markus Rainer (maxrainer18@gmail.com)
