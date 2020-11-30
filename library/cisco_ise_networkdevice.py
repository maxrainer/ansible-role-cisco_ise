#!/usr/bin/python
#
# Copyright (c) 2016, Markus Rainer <maxrainer18@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software
# and associated documentation files (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial
# portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
# FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
#TODOs:
# page / size when GET all
# SNMP v3
#
# flag force: if true all devices will be deleted and added again. This resets all passwords (even they are hidden)
# trustsec not supported


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
import json
import re
import copy
import urllib.request, urllib.parse, urllib.error
import urllib.request, urllib.error, urllib.parse

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

ISE_URL = {
        "networkdevice": "/ers/config/networkdevice"
    }

ISE_NSPC= {
        "networkdevice_json": "application/json",
        "networkdevice": "application/vnd.com.cisco.ise.network.networkdevice.1.1+xml",
        "networkdevice+utf":"application/vnd.com.cisco.ise.network.networkdevice.1.1+xml; charset=utf-8",
        "networkdevice+utf_json":"application/vnd.com.cisco.ise.network.networkdevice.1.1+json; charset=utf-8"
    }

NEEDED_DEFAULT_KEYS = [
    'radius_enabled','radius_shared_secrets','profile_name','snmp_enabled','snmp_version', 'snmp_polling_interval'
    ]
NEEDED_DEVICE_KEYS = ['ipaddress','name']

#---------------------------------------------------------------------------------------------------------------
def build_networkdevice_json (name, inner_json):
    result = '{"NetworkDevice" : {"name": "' + name + '",\n'
    result += inner_json+'}\n}'
    return result;
#---------------------------------------------------------------------------------------------------------------

def build_radius_json(radiusSharedSecret, keyInputFormat = "ASCII", enableKeyWrap = "false", hide_pwds=False):
    if hide_pwds:
        radiusSharedSecret = '******'
    result = '"authenticationSettings" : {"radiusSharedSecret" : "' + radiusSharedSecret +'",\n'
    result +='"enableKeyWrap" : "' + enableKeyWrap +'",\n'
    result +='"networkProtocol" : "RADIUS",\n'
    result +='"keyInputFormat" : "' + keyInputFormat +'"},\n'
    return result
#---------------------------------------------------------------------------------------------------------------
def build_networkdevice_iplist_json(ipaddress, mask = '32', coaPort = '1700'):
    result = '"coaPort" : "' + coaPort +'",\n'
    result += '"NetworkDeviceIPList" : [ {\n'
    result += ' "ipaddress" : "' + ipaddress +'","mask" : "' + str(mask) +'"} ],\n'
    return result
#---------------------------------------------------------------------------------------------------------------

def build_networkdevice_group_json(group_list, profileName = 'Cisco'):
    result = '"profileName" : "' + profileName +'",\n'
    result += '"NetworkDeviceGroupList" : ['
    for group in group_list:
        result += '"'+ group +'",'
    result = result[:-1]
    result +=']\n'
    return result
#---------------------------------------------------------------------------------------------------------------
def build_tacacs_json(tacacsSharedSecret, connectionMode ='OFF', hide_pwds=False):
    if hide_pwds:
        tacacsSharedSecret = '******'
    result = '"tacacsSettings" : {"connectModeOptions" : "' + connectionMode +'",\n'
    result +='"previousSharedSecretExpiry" : "0",\n'
    result +='"sharedSecret" : "' + tacacsSharedSecret +'"},\n'
    return result
#---------------------------------------------------------------------------------------------------------------
def build_snmp_json(roCommunity = 'public', version = '2c', pollingInterval = '28800',
        linkTrapQuery = 'true', macTrapQuery = 'true', originatingPolicyServicesNode = 'Auto',
        authPassword = 'changeme', authProtocol='MD5', securityLevel='AUTH', privacyPassword ='changeme',
        privacyProtocol='DES', username='user'):
    result = '"snmpsettings" : {'
    if version == '3' and not securityLevel == 'NO_AUTH':
        result += '"authPassword" : "' + privacyPassword +'",\n'
        result += '"authProtocol" : "' + authProtocol +'",\n'
    result += '"linkTrapQuery" : "' + linkTrapQuery +'",\n'
    result += '"macTrapQuery" : "' + macTrapQuery +'",\n'
    result += '"originatingPolicyServicesNode" : "' + originatingPolicyServicesNode +'",\n'
    result += '"pollingInterval" : "' + pollingInterval +'",\n'
    if version == '3' and securityLevel == 'PRIV':
        result += '"privacyPassword" : "' + privacyPassword +'",\n'
        result += '"privacyProtocol" : "' + privacyProtocol +'",\n'
    if version == '3':
        result += '"securityLevel" : "' + securityLevel +'",\n'
        result += '"username" : "' + username +'",\n'
    else:
        result += '"roCommunity" : "' + roCommunity +'",\n'
    v = 'TWO_C'
    if version == '3':
        v = "THREE"
    elif version == '1':
        v = "ONE"
    result += '"version" : "' + v +'"},\n'
    return result
#---------------------------------------------------------------------------------------------------------------
def build_add_body_json(device, outer=True, hide_pwds=False):
    inner = ''

    if "radius_enabled" in device:
        if device['radius_enabled']:
            inner += build_radius_json(device['radius_shared_secret'], hide_pwds=hide_pwds)
    if "mask" in device:
	    inner += build_networkdevice_iplist_json(device['ipaddress'],device['mask'],device['radius_coaport'])
    else:
        inner += build_networkdevice_iplist_json(device['ipaddress'],'',device['radius_coaport'])
    if device['tacacs_enabled']:
        inner += build_tacacs_json(device['tacacs_shared_secret'], device['tacacs_connection_mode'], hide_pwds=hide_pwds)
    if device['snmp_enabled'] == 'true':
        inner += build_snmp_json(roCommunity=device['snmp_ro_community'],version=device['snmp_version'],pollingInterval=device['snmp_polling_interval'],linkTrapQuery='true',macTrapQuery='true',originatingPolicyServicesNode = 'Auto',authPassword=device['snmp_v3_auth_password'],authProtocol=device['snmp_v3_auth_protocol'],securityLevel=device['snmp_v3_security_level'],privacyPassword=device['snmp_v3_privacy_password'],privacyProtocol=device['snmp_v3_privacy_protocol'],username=device['snmp_v3_username'])
    inner += build_networkdevice_group_json(device['network_device_groups'], profileName=device['profile_name'])

    if outer:
        result =  build_networkdevice_json(device['name'], inner)
        return result
    else:
        return inner
#---------------------------------------------------------------------------------------------------------------
def url_builder(ssl, server, port, extension):
    protocol = "https" if ssl else "http"
    return protocol + "://" + server + ":" + port + extension
#---------------------------------------------------------------------------------------------------------------
def add_networkdevice(body):

    url = url_builder(ssl, server, port, ISE_URL['networkdevice'])
    method = "POST"
    headers = {'Accept':ISE_NSPC['networkdevice_json'],
               'Content-Type':'application/json;charset=utf-8'}

    body = json.loads(body)
    body = json.dumps(body)

    con = open_url(url, data=body, headers=headers, method=method, use_proxy=False, force_basic_auth=True,
                   validate_certs=validate_certs,  url_username=username, url_password=password)

    if con.code == 201:
        return True
    return False

#---------------------------------------------------------------------------------------------------------------
def update_networkdevice_json(body, id):
    ISE_URL_with_ID = ISE_URL['networkdevice']+'/'+str(id)
    url = url_builder(ssl, server, port, ISE_URL_with_ID)
    method = "PUT"
    headers = {'Accept':ISE_NSPC['networkdevice_json'],
               'Content-Type':'application/json;charset=utf-8'}

    body = json.dumps(body)
#    print("-------- printing update body --------")
#    print(body)
#    print("-------- END UPDATE BODY --------")
    con = open_url(url, data=body, headers=headers, method=method, use_proxy=False, force_basic_auth=True,
                   validate_certs=validate_certs,  url_username=username, url_password=password)

    if con.code == 200:
        return True
#    print("======= CONN CODE  :  "+str(con.code) + " ==============")
    return False


#---------------------------------------------------------------------------------------------------------------
def get_all_networkdevices_json():
    page = 1
    result = {}
    while _get_all_networkdevices_json(page, result):
        page += 1
    return result
#---------------------------------------------------------------------------------------------------------------
def _get_all_networkdevices_json(page, result):
    url = url_builder(ssl, server, port, ISE_URL['networkdevice'] + '?size=100&page=' + str(page))
    method = "GET"
    headers = {'Accept':ISE_NSPC['networkdevice_json']}
    con = open_url(url, headers=headers, method=method, use_proxy=False, force_basic_auth=True,
                   validate_certs=validate_certs,  url_username=username, url_password=password)

    if con.code == 200:
        result_con_all = json.loads(con.read())
        result_total = result_con_all['SearchResult']['total']
        last = False
        for i, value in enumerate(result_con_all['SearchResult']['resources']):
            result[value['name']] = value['id']
        if (page * 100) >= result_total:
            last = True
        if not last:
            return True
    return False
#---------------------------------------------------------------------------------------------------------------
def get_networkdevice_details(uuid):
    url = url_builder(ssl, server, port, ISE_URL['networkdevice'] + '/' + uuid)
    method = "GET"
    headers = {'Accept':ISE_NSPC['networkdevice_json']}

    con = open_url(url, headers=headers, method=method, use_proxy=False, force_basic_auth=True,
                   validate_certs=validate_certs,  url_username=username, url_password=password)
    if con.code == 200:
        return con.read()

    return None
#---------------------------------------------------------------------------------------------------------------

# function to find if device exist on ISE (both by name or IP). If the name exists we don't want to overwrite.
# If device has different name but the same IP we won't be able to add new name
# 3 options as a result:
# 0 - no conflict, no devices found
# 1 - only one device found - can be updated
# 2 - two devices found - one having the same IP and another one with the conflicting name - can't update both
def check_if_device_exist(dev_IPaddr, dev_name):

    dev_already_exist_dict = {}
    dev_already_exist_list = []
    http_result = ''
    url = url_builder(ssl, server, port, ISE_URL['networkdevice'] + "?filter=ipaddress.CONTAINS."+ dev_IPaddr + "&filter=name.EQ." + dev_name + "&filtertype=or")
    method = "GET"

    headers = {'Accept':ISE_NSPC['networkdevice_json']}

    con = open_url(url, headers=headers, method=method, use_proxy=False, force_basic_auth=True,
                   validate_certs=validate_certs,  url_username=username, url_password=password)
    if con.code == 200:
        http_result = json.loads(con.read())

        if http_result['SearchResult']['total'] == 0:
            dev_already_exist_dict = {}

        elif http_result['SearchResult']['total'] == 1:
            name = http_result['SearchResult']['resources'][0]['name']
            id = http_result['SearchResult']['resources'][0]['id']
            # need to get device details to dig into IP / mask information
            device_found_details = json.loads(get_networkdevice_details(id))
            ip_value = device_found_details['NetworkDevice']['NetworkDeviceIPList'][0]['ipaddress']
            dev_already_exist_dict.update({"name" : name})
            dev_already_exist_dict.update({"id" : id})
            dev_already_exist_dict.update({"ipaddress" : ip_value})
            """ example of the result when 1 device found - dictionary lenght is 2
            {
                "name": "jsontest_4"
                "id": "1a792240-62cf-11ea-bea4-9a98c25ae02a",
                "ipaddress": "10.136.2.2"
            }
            """
            dev_already_exist_list.append(dev_already_exist_dict)

        elif http_result['SearchResult']['total'] == 2:

            for i, resource in enumerate(http_result['SearchResult']['resources']):
                dev_already_exist_dict = {}
                # ----- populating dictionary for 1st device found

                name = resource['name']
                id = resource['id']

                # need to get device details to dig into IP / mask information
                device_found_details = json.loads(get_networkdevice_details(id))
                ip_value = device_found_details['NetworkDevice']['NetworkDeviceIPList'][0]['ipaddress']

                dev_already_exist_dict.update({"name" : name})
                dev_already_exist_dict.update({"id" : id})
                dev_already_exist_dict.update({"ipaddress" : ip_value})

                dev_already_exist_list.append(dev_already_exist_dict)


    return dev_already_exist_list

#---------------------------------------------------------------------------------------------------------------
def delete_networkdevice(deviceid):
    url = url_builder(ssl, server, port, ISE_URL['networkdevice'] + "/" + deviceid)
    method = 'DELETE'
    headers = {'Accept':ISE_NSPC['networkdevice_json']}
    con = open_url(url, headers=headers, method=method, use_proxy=False, force_basic_auth=True,
                   validate_certs=validate_certs,  url_username=username, url_password=password)
    if con.code == 204:
        return True
    return False
#---------------------------------------------------------------------------------------------------------------
def feed_networkdevices_with_default(orig_networkdevices_table, defaults):
    result = {}
    networkdevices_table = copy.deepcopy(orig_networkdevices_table)
    for dev in networkdevices_table:
        for key in list(defaults.keys()):
            if not key in dev:
                dev[key] = defaults[key]
        result[dev['name']] = dev
    return result
#---------------------------------------------------------------------------------------------------------------
def feed_networkdevice_with_paramfromISE(networkdevice, ise_param):

    netdevice = copy.deepcopy(networkdevice)
    ise_param_updated = copy.deepcopy(ise_param)
#    print("---------- PROVIDED BY USER ---------------")
#    print(netdevice)
#    print("----------- FROM ISE  -----------")
#    print(ise_param_updated)
#    print("--------END FEED---------")
    for key in list(netdevice.keys()):
        #---------GENERAL fields for "NetworkDevice":  --------
        if key == "name":
            ise_param_updated['NetworkDevice']['name'] = netdevice['name']
        if key == "radius_coaport":
            ise_param_updated['NetworkDevice']['coaPort'] = netdevice['radius_coaport']
        if key == "ipaddress":
            ise_param_updated['NetworkDevice']['NetworkDeviceIPList'][0]['ipaddress'] = netdevice['ipaddress']
        if key == "mask":
            ise_param_updated['NetworkDevice']['NetworkDeviceIPList'][0]['mask'] = netdevice['mask']
        #--------- SNMP fields --------
        if key == "snmp_enabled":
            if netdevice['snmp_enabled'] == 'true':
                if "snmp_version" in netdevice:
                    if netdevice['snmp_version'] == '2c':
                        ise_param_updated['NetworkDevice']['snmpsettings']['version'] = 'TWO_C'
                        if "snmp_ro_community" in netdevice:
                            ise_param_updated['NetworkDevice']['snmpsettings']['roCommunity'] = netdevice['snmp_ro_community']
                    if netdevice['snmp_version'] == '1':
                        ise_param_updated['NetworkDevice']['snmpsettings']['version'] = 'ONE'
                        if "snmp_ro_community" in netdevice:
                            ise_param_updated['NetworkDevice']['snmpsettings']['roCommunity'] = netdevice['snmp_ro_community']
                    if netdevice['snmp_version'] == '3':
                        ise_param_updated['NetworkDevice']['snmpsettings']['linkTrapQuery'] = 'true'
                        ise_param_updated['NetworkDevice']['snmpsettings']['macTrapQuery'] = 'true'
                        ise_param_updated['NetworkDevice']['snmpsettings']['version'] = 'THREE'
                        if "snmp_v3_username" in netdevice:
                            ise_param_updated['NetworkDevice']['snmpsettings']['username'] = netdevice['snmp_v3_username']
                        if "snmp_v3_security_level" in netdevice:
                            ise_param_updated['NetworkDevice']['snmpsettings']['securityLevel'] = netdevice['snmp_v3_security_level']

                            if netdevice['snmp_v3_security_level'] == 'NO_AUTH':
                                ise_param_updated['NetworkDevice']['snmpsettings'].pop('authProtocol', None)
                                ise_param_updated['NetworkDevice']['snmpsettings'].pop('authPassword', None)
                                ise_param_updated['NetworkDevice']['snmpsettings'].pop('privacyProtocol', None)
                                ise_param_updated['NetworkDevice']['snmpsettings'].pop('privacyPassword', None)
                            if not netdevice['snmp_v3_security_level'] == 'NO_AUTH':
                                if "snmp_v3_auth_protocol" in netdevice:
                                    ise_param_updated['NetworkDevice']['snmpsettings']['authProtocol'] = netdevice['snmp_v3_auth_protocol']
                            if "snmp_v3_auth_password" in netdevice:
                                    ise_param_updated['NetworkDevice']['snmpsettings']['authPassword'] = netdevice['snmp_v3_auth_password']

                            if netdevice['snmp_v3_security_level'] == 'PRIV':
                                if "snmp_v3_privacy_protocol" in netdevice:
                                    ise_param_updated['NetworkDevice']['snmpsettings']['privacyProtocol'] = netdevice['snmp_v3_privacy_protocol']
                                if "snmp_v3_privacy_password" in netdevice:
                                    ise_param_updated['NetworkDevice']['snmpsettings']['privacyPassword'] = netdevice['snmp_v3_privacy_password']


                if "snmp_pooling_interval" in netdevice:
                    ise_param_updated['NetworkDevice']['snmpsettings']['pollingInterval'] = netdevice['snmp_polling_interval']
            else:
                ise_param_updated['NetworkDevice'].pop('snmpsettings', None)
        #--------- TACACS fields --------
        if key == "tacacs_enabled":
            if netdevice['tacacs_enabled'] == True:
                #if TACACS was not used in ISE for that device we need to initialize this dectionary to update specific fields
                if 'tacacsSettings' not in list(ise_param_updated['NetworkDevice'].keys()):
                    ise_param_updated['NetworkDevice']['tacacsSettings'] = {}
                    ise_param_updated['NetworkDevice']['tacacsSettings']['sharedSecret'] = "test"
                    ise_param_updated['NetworkDevice']['tacacsSettings']['connectModeOptions'] = "OFF"
                    ise_param_updated['NetworkDevice']['tacacsSettings']['previousSharedSecretExpiry'] = "0"
                if "tacacs_shared_secret" in netdevice:
                    ise_param_updated['NetworkDevice']['tacacsSettings']['sharedSecret'] = netdevice['tacacs_shared_secret']
                if "tacacs_connection_mode" in netdevice:
                    ise_param_updated['NetworkDevice']['tacacsSettings']['connectModeOptions'] = netdevice['tacacs_connection_mode']

            else:
                ise_param_updated['NetworkDevice'].pop('tacacsSettings', None)
        #--------- RADIUS fields --------
        if key == "radius_enabled":
            if netdevice['radius_enabled'] == True:
                if "radius_shared_secret" in netdevice:
                    ise_param_updated['NetworkDevice']['authenticationSettings']['radiusSharedSecret'] = netdevice['radius_shared_secret']
                # to be completed 

            else:
                ise_param_updated['NetworkDevice']['authenticationSettings']['radiusSharedSecret'] = ''
                ise_param_updated['NetworkDevice']['authenticationSettings'].pop('networkProtocol', None)
        #---------- DEVICE GROUP membership ---------
        if key == "network_device_groups":
            ise_param_updated['NetworkDevice']['NetworkDeviceGroupList'] = netdevice['network_device_groups']

    return ise_param_updated
#---------------------------------------------------------------------------------------------------------------
def find_original_networkdevice_before_populating_defaults(networkdevices, dev_name):
    result = {}
    for i, value in enumerate(networkdevices):
        if networkdevices[i]['name'] == dev_name:
            result = networkdevices[i]
    return result
#---------------------------------------------------------------------------------------------------------------
def main():
    global ssl, username, password, validate_certs, server, port, force
    server = port = username = password = ""
    ssl = validate_certs = force = False
    
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(type='str', required=True),
            port=dict(type='str', required=False, default="9060"),
            username=dict(type='str', aliases=['user'], required=True),
            password=dict(type='str', aliases=['pass', 'pwd'], required=True),
            ssl=dict(default=True, type='bool'),
            validate_certs=dict(default=False, type='bool'),
            delete_devices=dict(default=False, type='bool'),
            networkdevices=dict(required=True, type='json', aliases=['device','devices']),
            mgmt_defaults=dict(required=True, type='dict', aliases=['defaults'])
        )
    )

    server = module.params['host']
    port = module.params['port']
    username = module.params['username']
    password = module.params['password']
    ssl = module.params['ssl']
    validate_certs = module.params['validate_certs']
    delete_devices= module.params['delete_devices']
    networkdevices = module.params['networkdevices']
    defaults = module.params['mgmt_defaults']
    """
    #networkdevices = "[{\"ipaddress\":\"192.163.102.29\",\"name\":\"BBCR01.OMA11.N.ZZ\"},{\"ipaddress\":\"192.168.142.28\",\"name\":\"4333\"}]"
    #networkdevices = "[{\"ipaddress\":\"192.168.102.29\",\"name\":\"travi333stest\",\"radius_coaport\":\"1799\",\"network_device_groups\":[\"OWNERSHIP#OWNERSHIP#CLIENT\"], \"snmp_enabled\":\"true\"}]"
    defaults = {
        # this one was added - IMPORTANT to implement different mask - should be provided
        "mask":"32",
		"snmp_enabled":"true",
		"snmp_version":"2c",
		"snmp_polling_interval":"28800",
		"snmp_ro_community":"new_public_string",
        # this one is not needed - its not on the list
		"snmp_rw_community":"new_rw_string",
		"snmp_v3_username":"snmpv3user",
		"snmp_v3_auth_protocol":"MD5",
		"snmp_v3_auth_password":"changeme",
		"snmp_v3_privacy_protocol":"DES",
		"snmp_v3_privacy_password":"changeme",
		"snmp_v3_security_level":"AUTH",
		"tacacs_enabled":"true",
		"tacacs_shared_secret":"alamakota",
		"tacacs_connection_mode":"ON_LEGACY",
		"radius_enabled":"true",
		"radius_shared_secret":"changeme",
		"radius_enable_keywrap":"false",
		"radius_coaport":"1600",
		"profile_name":"Cisco",
		"network_device_groups": ["Location#All Locations","Device Type#All Device Types"]
    }
    """
    count_deleted = count_added = count_changed = 0
    changed = False
    device_exist_dict = {}

    try:
        ise_networkdevices = get_all_networkdevices_json()
        networkdevices = json.loads(networkdevices)
#        print("---------- ORIGINAL USERS -------")
#        print(str(networkdevices))
#        print("---------- ORIGINAL END -------")
        if delete_devices == True:
            #print("========= TRYING TO DELETE =============")
            i = 0
            for i, device_name_dict in enumerate(networkdevices):
                #print("========= DELETE: FOR: checking if device exist by name or IP. : " + json.dumps(device_name_dict, indent = 3))
                device_exist_list = []
                device_exist_list = check_if_device_exist(device_name_dict['ipaddress'], device_name_dict['name'])

                if len(device_exist_list) == 1:
                    if delete_networkdevice(device_exist_list[0]['id']):
                        count_deleted += 1
                    else:
                        module.fail_json(msg="Failure when deleting Device: '%s' with ID: '%s'." % (device_name_dict['name'], device_name_dict['id']))
                else:
                    module.fail_json(msg="Failed to delete Device: '%s': " % device_name_dict['name'])
        else:
            # populating all fields for specific device - taking defaults if not provided by user
            device_dict = feed_networkdevices_with_default(networkdevices, defaults)
            # add devices from device_dict but only if the device doesn't exist (compare to device_exist_dict)
            # if device exists - try to update. Can be updated only if there is one device (having provided IP or name)
        
            for device_name in list(device_dict.keys()):
                device_exist_list = []
                device_exist_list = check_if_device_exist(device_dict[device_name]['ipaddress'], device_name)
                device = device_dict[device_name]
        
                # if device doesn't exist just simply add it
                if len(device_exist_list) == 0:        
                    #print("========= TRYING TO ADD DEVICES =============")
                    add_body = build_add_body_json(device)
                    if not add_networkdevice(add_body):
                        #print("========= FAILED TO ADD DEVICES =============")
                        module.fail_json(msg="Failed to add Device: '%s': " % device_name)
                    count_added += 1
                # if only 1 device exists (list's lenght is 1) - check what to update. 2 devices means possible conflict - none will be updated
                elif len(device_exist_list) == 1:
                    #print("========= TRYING TO UPDATE =============")        
                    dev_id = device_exist_list[0]['id']
                    ise_detail_str = get_networkdevice_details(dev_id)
                    ise_detail_dict = json.loads(ise_detail_str)
                    result_original = find_original_networkdevice_before_populating_defaults(networkdevices, device_name)
                    result_feeded = feed_networkdevice_with_paramfromISE(result_original,ise_detail_dict)
        
                    update_result = update_networkdevice_json(result_feeded, dev_id)
                    if update_result == True:
                        count_changed += 1
                    else:
                        raise Exception("Not able to get detail for device '%s'" % device_name)
                else:
                    module.fail_json(msg="2 Devices found - possible conflict. Failed to update Device: '%s': " % device_name)        
        
        # result handling
        if (count_deleted > 0 or count_changed > 0 or count_added > 0):
            changed = True
        module.exit_json(changed=changed, meta="Network Devices total work done: %d, added: %d, deleted: %d, changed: %d." % ((count_added+count_changed+count_deleted), count_added, count_deleted, count_changed))
    
    except urllib.error.HTTPError as ex:
        msg = 'empty error code | might be realated to ISE itself'
        try:
            tree = ET.fromstring(ex.read())
            t = tree.find('messages/message/title')
            if t is not None:
                msg = t.text
        except:
            pass
        module.fail_json(msg="HTTP Connection Error. HTTP Code: " + str(ex.code) + ", Status: " + ex.msg + ", Message: " + msg)

    except Exception as ex:
        module.fail_json(msg="Undefined Error or missing variable: " + str(ex))    




if __name__ == '__main__':
    main()
