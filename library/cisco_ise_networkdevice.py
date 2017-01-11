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
import urllib2
from __builtin__ import False
try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

ISE_URL = {
        "networkdevice": "/ers/config/networkdevice"
    }

ISE_NSPC= {
        "networkdevice": "application/vnd.com.cisco.ise.network.networkdevice.1.1+xml",
        "networkdevice+utf":"application/vnd.com.cisco.ise.network.networkdevice.1.1+xml; charset=utf-8"
    }

NEEDED_DEFAULT_KEYS = [
    'radius_enabled','radius_shared_secrets','profile_name','snmp_enabled','snmp_version', 'snmp_polling_interval'
    ]
NEEDED_DEVICE_KEYS = ['ipaddress','name']

def build_networkdevice_xml(name, inner_xml):
    result = '<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n'
    result += '<ns4:networkdevice name="' + name + '" xmlns:ers="ers.ise.cisco.com" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:ns4="network.ers.ise.cisco.com">\n'
    result += inner_xml
    result += '</ns4:networkdevice>\n'
    return result;

def build_radius_xml(radiusSharedSecret, keyInputFormat = "ASCII", enableKeyWrap = "false", hide_pwds=False):
    if hide_pwds:
        radiusSharedSecret = '******'
    result = '<authenticationSettings>\n'
    result += '<enableKeyWrap>' + enableKeyWrap + '</enableKeyWrap>\n'
    result += '<keyInputFormat>' + keyInputFormat + '</keyInputFormat>\n'
    result += '<networkProtocol>RADIUS</networkProtocol>\n'
    result += '<radiusSharedSecret>' + radiusSharedSecret + '</radiusSharedSecret>\n'
    result += '</authenticationSettings>\n'
    result += ''
    return result

def build_networkdevice_iplist_xml(ipaddress, mask='32', coaPort = '1700'):
    result = '<coaPort>' + coaPort  + '</coaPort>\n'
    result += '<NetworkDeviceIPList>\n'
    result += '<NetworkDeviceIP>\n'
    result += '<ipaddress>' + ipaddress + '</ipaddress>\n'
    result += '<mask>' + mask + '</mask>'
    result += '</NetworkDeviceIP>\n'
    result += '</NetworkDeviceIPList>\n'

    return result

def build_networkdevice_group_xml(group_list, profileName = 'Cisco'):
    result = '<NetworkDeviceGroupList>\n'
    for group in group_list:
        result += '<NetworkDeviceGroup>' + group + '</NetworkDeviceGroup>\n'
    result += '</NetworkDeviceGroupList>\n'
    result += '<profileName>' + profileName + '</profileName>\n'
    return result
 
def build_tacacs_xml(tacacsSharedSecret, connectionMode ='OFF', hide_pwds=False):
    if hide_pwds:
        tacacsSharedSecret = '******'
    result = '<tacacsSettings>\n'
    result += '<connectModeOptions>' + connectionMode + '</connectModeOptions>\n'
    result += '<previousSharedSecretExpiry>0</previousSharedSecretExpiry>\n'
    result += '<sharedSecret>' + tacacsSharedSecret + '</sharedSecret>\n'
    result += '</tacacsSettings>\n'
    return result

# snmp v3 missing
def build_snmp_xml(roCommunity = 'public', version = '2c', pollingInterval = '28800',
        linkTrapQuery = 'true', macTrapQuery = 'true', originatingPolicyServicesNode = 'Auto', 
        authPassword = 'changeme', authProtocol='MD5', securityLevel='AUTH', privacyPassword ='changeme',
        privacyProtocol='DES', username='user'):
    result = '<snmpsettings>\n'
    if version == '3' and not securityLevel == 'NO_AUTH':
            result += '<authPassowrd>' + authPassword + '</authPassowrd>\n'
            result += '<authProtocol>' + authProtocol +  '</authProtocol>\n'
    result += '<linkTrapQuery>' + linkTrapQuery + '</linkTrapQuery>\n'
    result += '<macTrapQuery>' + macTrapQuery + '</macTrapQuery>\n'
    result += '<originatingPolicyServicesNode>' + originatingPolicyServicesNode + '</originatingPolicyServicesNode>\n'
    result += '<pollingInterval>' + pollingInterval + '</pollingInterval>\n'
    if version == '3' and securityLevel == 'PRIV':
        result += '<privacyPassowrd>' + privacyPassword + '</privacyPassowrd>\n'
        result += '<privacyProtocol>' + privacyProtocol + '</privacyProtocol>\n'
    if version == '3':
        result += '<securityLevel>' + securityLevel + '</securityLevel>\n'
        result += '<username>' + username + '</username>\n'   
    else:
        result += '<roCommunity>' + roCommunity + '</roCommunity>\n'

    v = 'TWO_C'
    if version == '3':
        v = "THREE"
    elif version == '1':
        v = "ONE"
    result += '<version>' + v + '</version>\n'
    result += '</snmpsettings>\n'
    return result

def build_add_body(device, outer=True, hide_pwds=False):
    inner = ''
    if device['radius_enabled']:
        inner += build_radius_xml(device['radius_shared_secret'], hide_pwds=hide_pwds)
    inner += build_networkdevice_iplist_xml(device['ipaddress'])
    inner += build_networkdevice_group_xml(device['network_device_groups'], profileName=device['profile_name'])
    if device['snmp_enabled']:
        inner += build_snmp_xml(device['snmp_ro_community'], device['snmp_version'], device['snmp_polling_interval'], 
                                username=device['snmp_v3_username'], authProtocol=device['snmp_v3_auth_protocol'], 
                                authPassword=device['snmp_v3_auth_password'], privacyProtocol=device['snmp_v3_privacy_protocol'], 
                                privacyPassword=device['snmp_v3_privacy_password'], securityLevel=device['snmp_v3_security_level'] )
    if device['tacacs_enabled']:
        inner += build_tacacs_xml(device['tacacs_shared_secret'], device['tacacs_connection_mode'], hide_pwds=hide_pwds)
    if outer:
        result =  build_networkdevice_xml(device['name'], inner)
        return result
    else:
        return inner

def url_builder(ssl, server, port, extension):
    protocol = "https" if ssl else "http"
    return protocol + "://" + server + ":" + port + extension

def add_networkdevice(body):
    url = url_builder(ssl, server, port, ISE_URL['networkdevice'])
    method = "POST"
    headers = {'Accept':ISE_NSPC['networkdevice'],
               'Content-Type':ISE_NSPC['networkdevice+utf']}
    con = open_url(url, data=body, headers=headers, method=method, use_proxy=False, force_basic_auth=True, 
                   validate_certs=validate_certs,  url_username=username, url_password=password)
    if con.code == 201:
        return True
    return False

def get_all_networkdevices():
    page = 1
    result = {}
    while _get_all_networkdevices(page, result):
        page += 1
    return result

def _get_all_networkdevices(page, result):
    url = url_builder(ssl, server, port, ISE_URL['networkdevice'] + '?size=100&page=' + str(page))
    method = "GET"
    headers = {'Accept':ISE_NSPC['networkdevice']}
    con = open_url(url, headers=headers, method=method, use_proxy=False, force_basic_auth=True, 
                   validate_certs=validate_certs,  url_username=username, url_password=password)
    if con.code == 200:
        tree = ET.fromstring(con.read())
        last = False
        for e in tree.iter():
            if (e.tag == 'resource' and e.get('name')):
                result[e.get('name')] =  e.get('id')
            if (e.attrib.get('total') != None):
                total = int(e.attrib.get('total'))
                if  total == 0:
                    return False
                if (page * 100) >= total:
                    last = True 
        if not last:
            return True
    return False

def get_networkdevice_details(uuid):
    url = url_builder(ssl, server, port, ISE_URL['networkdevice'] + '/' + uuid)
    method = "GET"
    headers = {'Accept':ISE_NSPC['networkdevice']}
    con = open_url(url, headers=headers, method=method, use_proxy=False, force_basic_auth=True, 
                   validate_certs=validate_certs,  url_username=username, url_password=password)
    if con.code == 200:
        return con.read()
    
    return None

def delete_networkdevice(deviceid):
    url = url_builder(ssl, server, port, ISE_URL['networkdevice'] + "/" + deviceid)
    method = 'DELETE'
    headers = {'Accept':ISE_NSPC['networkdevice']}
    con = open_url(url, headers=headers, method=method, use_proxy=False, force_basic_auth=True, 
                   validate_certs=validate_certs,  url_username=username, url_password=password)
    if con.code == 204:
        return True
    return False

def feed_networkdevices(networkdevices, defaults):
    result = {}
    for device in networkdevices:
        for key in defaults.keys():
            if not key in device:
                device[key] = defaults[key]
        result[device['name']] = device
    return result

def diff(ise_networkdevices, device_dict):
    to_delete = []
    unchanged = []
    to_add = device_dict.keys()
    for ise_device_name in ise_networkdevices.keys():
        if not ise_device_name in device_dict or force:
            to_delete.append(ise_device_name)
        else:
            unchanged.append(ise_device_name)
            to_add.remove(ise_device_name)
    return [to_add, to_delete, unchanged]

def is_equal(ise_config, ansible_config, radius_enabled):
    regex_begin = 'networkdevice.*?/>'
    # workaround for API always shows some RADIUS entries
    if not radius_enabled:
        if  re.match('.*<networkProtocol>RADIUS</networkProtocol>.*', ise_config):
            return False
        regex_begin = '</authenticationSettings>'
    m = re.search(regex_begin + '(.*)</ns.*?networkdevice>', ise_config)
    ise_config = m.group(1)
    ansible_config = ansible_config.replace("\n","")
    return ise_config == ansible_config

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
            force=dict(default=False, type='bool'),
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
    force = module.params['force']
    networkdevices = module.params['networkdevices']
    defaults = module.params['mgmt_defaults']
    
    count_deleted = count_added = count_changed = 0
    changed = False
                
    try:
        ise_networkdevices = get_all_networkdevices()
        # this maybe we can delete!!!
        networkdevices = json.loads(networkdevices)
        device_dict = feed_networkdevices(networkdevices, defaults)
        # both hold list of device names
        [to_add, to_delete, unchanged] = diff(ise_networkdevices, device_dict)
        
        # delete devices from to_delete
        for device_name in to_delete:
            if delete_networkdevice(ise_networkdevices[device_name]):
                count_deleted += 1 
            else: 
                module.fail_json(msg="Failure when deleting Device: '%s' with ID: '%s'." % (device_name, ise_networkdevices[device_name]))
        
        # add devices from to_add
        for device_name in to_add:
            device = device_dict[device_name]
            body = build_add_body(device)
            if not add_networkdevice(body):
                module.fail_json(msg="Failed to add Device: '%s': " % device_name)
            count_added += 1
            
        # find changes in all other devices (not added or deleted)
        for device_name in unchanged:
            device = device_dict[device_name]
            ise_detail = get_networkdevice_details(ise_networkdevices[device_name])
            ansible_config = build_add_body(device, False, True)
            if not ise_detail:
                raise Exception("Not able to get detail for device '%s'" % device_name)
            if not is_equal(ise_detail, ansible_config, device['radius_enabled']):
                delete_networkdevice(ise_networkdevices[device_name])
                body = build_add_body(device)
                add_networkdevice(body)
                count_changed += 1
        
        # result handling
        if (count_deleted > 0 or count_changed > 0 or count_added > 0):
            changed = True
        module.exit_json(changed=changed,
                         meta="Network Devices total work done: %d, added: %d, deleted: %d, changed: %d." % ((count_added+count_changed+count_deleted), count_added, count_deleted, count_changed))
        
        
    except urllib2.HTTPError as ex:
        msg = 'empty'
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