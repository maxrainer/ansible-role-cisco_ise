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

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from urllib2 import URLError
from time import sleep
import re
import urllib2
try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

ISE_URL = {
    "endpoint": "/ers/config/endpoint",
    "endpointgroup": "/ers/config/endpointgroup",
    "endpointbulk": "/ers/config/endpoint/bulk"
}

ISE_NSPC= {
       "endpointbulkrequest": "application/vnd.com.cisco.ise.identity.endpointbulkrequest.1.0+xml; charset=utf-8",
       "endpointgroup": "application/vnd.com.cisco.ise.identity.endpointgroup.1.0+xml",
       "endpoint": "application/vnd.com.cisco.ise.identity.endpoint.1.0+xml",
       "bulkstatus": "application/vnd.com.cisco.ise.identity.bulkStatus.1.0+xml"
    }

SLEEP_TIMER = 2

class endpoint():
    
    def __init__(self, uuid, name, description):
        self.name = name
        self.uuid = uuid
        self.description = description
    
def build_endpoint(macaddress):
    result = '<ns5:endpoint description="' + macaddress + '">\n'
    result += '<groupId>' + group_id + '</groupId>\n'
    result += '<mac>' + macaddress + '</mac>\n'
    result += '<staticGroupAssignment>true</staticGroupAssignment>\n'
    result += '<staticProfileAssignment>false</staticProfileAssignment>\n'
    result += '</ns5:endpoint>\n'
    return result  

def build_endpoint_outer(macaddress):
    result = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    result += '<ns5:endpoint description="' + macaddress + '" id="id" name="name" xmlns:ers="ers.ise.cisco.com" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:ns5="identity.ers.ise.cisco.com">\n'
    result += '<groupId>' + group_id + '</groupId>\n'
    result += '<mac>' + macaddress + '</mac>\n'
    result += '<staticGroupAssignment>true</staticGroupAssignment>\n'
    result += '<staticProfileAssignment>false</staticProfileAssignment>\n'
    result += '</ns5:endpoint>\n'
    return result  
  
def build_endpoint_bulk_request(inner_data):
    result = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    result += '<ns2:bulkRequest xsi:type="ns5:endpointBulkRequest" operationType="create" resourceMediaType="vnd.com.cisco.ise.identity.endpoint.1.0+xml" xmlns:ns6="anc.ers.ise.cisco.com" xmlns:ns5="identity.ers.ise.cisco.com" xmlns:ns7="sxp.ers.ise.cisco.com" xmlns:ns2="ers.ise.cisco.com" xmlns:ns4="network.ers.ise.cisco.com" xmlns:ns3="trustsec.ers.ise.cisco.com" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n'
    result += '<ns5:resourcesList>\n'
    result += inner_data
    result += '</ns5:resourcesList>\n'
    result += '</ns2:bulkRequest>'
    return result

def build_endpoint_delete_bulk_request(inner_data):
    result = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    result += '<ns2:bulkRequest xsi:type="ns5:endpointBulkRequest" operationType="delete" resourceMediaType="vnd.com.cisco.ise.identity.endpoint.1.0+xml" xmlns:ns6="anc.ers.ise.cisco.com" xmlns:ns5="identity.ers.ise.cisco.com" xmlns:ns7="sxp.ers.ise.cisco.com" xmlns:ns2="ers.ise.cisco.com" xmlns:ns4="network.ers.ise.cisco.com" xmlns:ns3="trustsec.ers.ise.cisco.com" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n'
    result += '<idList>\n'
    result += inner_data
    result += '</idList>'
    result += '</ns2:bulkRequest>'
    return result

def chunks(l, n):
    return (l[i:i+n] for i in xrange(0, len(l), n))

def is_valid_mac(mac):
    if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()):
        return True
    return False

def get_count(xml_tree, attribute):
    for element in xml_tree.iter():
        if (element.attrib.get(attribute) != None):
            return int(element.attrib.get(attribute))
    return 0

def get_attribute(xml_tree, tag, attribute):
    for e in xml_tree.iter():
        if e.tag == tag and e.attrib.get(attribute) != None:
            return e.attrib.get(attribute)
    return ""

def exec_is_completed(xml_tree):
    for element in xml_tree.iter():
        if (element.attrib.get("executionStatus") != None):
            status = element.attrib.get("executionStatus")
            if (status == "COMPLETED"):
                return True
            return False
    return False

def collect_failed_macs(xml_tree):
    result = []
    for element in xml_tree.iter():
        if (element.attrib.get('status') != None and element.attrib.get('status') == 'FAIL'):
            mac = element.attrib.get('description')
            result.append(mac)
    return result
             
def get_group_id(identitygroup):
    url = url_builder(ssl, server, port, ISE_URL['endpointgroup'] + "?filter=name.EQ." + identitygroup)
    headers = {'Accept': ISE_NSPC['endpointgroup']}
    method = "GET"
    con = open_url(url, headers=headers, method=method, use_proxy=False,force_basic_auth=True, 
                   validate_certs=validate_certs, url_username=username, url_password=password )
    tree = ET.fromstring(con.read())
    for e in tree.iter():
        if (e.attrib.get('total') != None):
            if (e.attrib.get('total') == '0'):
                return ""
        if (e.attrib.get('id') != None):
            result = e.attrib.get('id')
            return result
    return ""

def get_endpoints_by_group(group_id):
    page = 1
    result = {}
    while _get_endpoints_by_group(group_id, page, result):
        page += 1
    return result

def _get_endpoints_by_group(group_id, page, result):
    url = url_builder(ssl, server, port, ISE_URL['endpoint'] + "?filter=groupId.EQ." + group_id + "&page=" + str(page) + "&size=100")
    headers = {'Accept': ISE_NSPC['endpoint']}
    method = "GET"
    try:
        con = open_url(url, headers=headers, method=method, use_proxy=False,force_basic_auth=True, 
                       validate_certs=validate_certs,  url_username=username, url_password=password)
    except urllib2.HTTPError:
        return False
    if con.code == 200:
        tree = ET.fromstring(con.read())
        for e in tree.iter():
            if (e.tag == 'resource'):
                ep = endpoint(e.get('id'),e.get('name'),e.get('description'))
                result[e.get('name')] = ep
            if (e.attrib.get('total') != None):
                if (e.attrib.get('total') == '0'):
                    return False
        return True
    return False

def delete_endpoint_bulk(endpoint_id_list):
    chunked = chunks(endpoint_id_list, 500)
    for l in chunked:
        if not _delete_endpoint_bulk(l):
            return False
    return True

def _delete_endpoint_bulk(endpoint_id_list):
    global del_count
    url = url_builder(ssl, server, port, ISE_URL['endpointbulk'])
    method = "PUT"
    headers = {'Content-Type':ISE_NSPC['endpointbulkrequest']}
    inner_data = ""
    for endpoint_id in endpoint_id_list:
        inner_data += "<id>" + endpoint_id + "</id>\n"
    data = build_endpoint_delete_bulk_request(inner_data)
    con = open_url(url,data=data, headers=headers, method=method, use_proxy=False,force_basic_auth=True, 
                   validate_certs=validate_certs,  url_username=username, url_password=password)
    if con.code == 202:
        if check_endpoint_delete_bulk_result(con.headers['location']):
            del_count += len(endpoint_id_list)
            return True
    return False

# Bulk API supports max. 500 Endpoints
def put_endpoint_bulk(macaddress_list):
    chunked = chunks(macaddress_list, 500)
    for l in chunked:
        if not _put_endpoint_bulk(l):
            return False
    return True

def _put_endpoint_bulk(macaddress_list):
    global change_count
    url = url_builder(ssl, server, port, ISE_URL['endpointbulk'])
    method = "PUT"
    headers = {'Content-Type':ISE_NSPC['endpointbulkrequest']}
    inner_data = ""
    for macaddress in macaddress_list:
        inner_data += build_endpoint(macaddress)
    data = build_endpoint_bulk_request(inner_data)
    con = open_url(url,data=data, headers=headers, method=method, use_proxy=False,force_basic_auth=True, 
                   validate_certs=validate_certs,  url_username=username, url_password=password)
    if con.code == 202:
        check_endpoint_bulk_result(con.headers['location'])
        return True
    return False

def get_endpoint_id(macaddress):
    url = url_builder(ssl, server, port, ISE_URL['endpoint'] + '?filter=mac.EQ.' + macaddress)
    method = "GET"
    headers = {'Accept': ISE_NSPC['endpoint']}
    con = open_url(url, headers=headers, method=method, use_proxy=False, force_basic_auth=True, 
                   validate_certs=validate_certs,  url_username=username, url_password=password)
    if con.code == 200:
        tree = ET.fromstring(con.read())
        endpoint_id = get_attribute(tree, "resource", "id")
        return endpoint_id
    return ""
   
def put_endpoint(macaddress):
    url = url_builder(ssl, server, port, ISE_URL['endpoint'])
    method = "POST"
    headers = {'Content-Type':ISE_NSPC['endpoint']}
    data = build_endpoint_outer(macaddress)    
    con = open_url(url, data=data, headers=headers, method=method, use_proxy=False, force_basic_auth=True, 
                   validate_certs=validate_certs,  url_username=username, url_password=password)
    if con.code == 201:
        return True
    return False
    
def retry_endpoints_by_mac(macaddress_list):
    global change_count, failed_macs
    put_mac_list = []
    delete_id_list = []
    for macaddress in macaddress_list:
        endpoint_id = get_endpoint_id(macaddress)
        if endpoint_id:
            delete_id_list.append(endpoint_id)
            put_mac_list.append(macaddress)
    if delete_id_list:
        delete_endpoint_bulk(delete_id_list)
    if put_mac_list:
        put_endpoint_bulk(put_mac_list)
   
def check_endpoint_delete_bulk_result(status_location):
    global change_count, failed_macs
    ready = False
    count = 0
    while not ready and count < (timeout / SLEEP_TIMER):
        tree = get_endpoint_bulk_status(status_location)
        ready = exec_is_completed(tree)
        if not ready: 
            sleep(SLEEP_TIMER)
            count +=1
    if ready:
        failCount = get_count(tree, "failCount")
        if (failCount == 0):
            return True
    return False 
    
 
def check_endpoint_bulk_result(status_location):
    global change_count
    ready = False
    count = 0
    while not ready and count < (timeout / SLEEP_TIMER):
        tree = get_endpoint_bulk_status(status_location)
        ready = exec_is_completed(tree)
        if not ready: 
            sleep(SLEEP_TIMER)
            count +=1
    if ready:
        failCount = get_count(tree, "failCount")
        if failCount > 0:
            failed_mac_list = collect_failed_macs(tree)
            retry_endpoints_by_mac(failed_mac_list)
        else:
            change_count += get_count(tree, "successCount")
        return True
    return False
    

def get_endpoint_bulk_status(status_location):
    method = "GET"
    headers = {'Accept':ISE_NSPC['bulkstatus']}
    con = open_url(url=status_location, headers=headers, method=method, use_proxy=False,force_basic_auth=True, 
                   validate_certs=validate_certs,  url_username=username, url_password=password)
    if not con.code == 200:
        return ""
    return ET.fromstring(con.read())

# returns 2 values: 1) delta to add, 2) remove list
def delta_mac_list(mac_given, endpoints_ise):
    unique = list(set(mac_given))
    delta = []
#    mac_ise_set = set(endpoints_ise.values())
    if not endpoints_ise:
        return [mac_given, []]
    for mac in unique:
        mac = mac.upper()
        if is_valid_mac(mac):
            if not mac in endpoints_ise:
                delta.append(mac)
            else:
                del endpoints_ise[mac]
    return [delta,endpoints_ise]


def url_builder(ssl, server, port, extension):
    protocol = "https" if ssl else "http"
    return protocol + "://" + server + ":" + port + extension

def main():
    global server, port, username, password, ssl, validate_certs, group_id, identitygroup
    global timeout, changed, failed, change_count, add_count, del_count, failed_macs
    server = port = username = password = identitygroup = ""
    ssl = validate_certs = changed = failed =  False
    change_count = del_count = add_count =  0
    failed_macs = []
    
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(type='str', required=True),
            port=dict(type='str', required=False, default="9060"),
            username=dict(type='str', aliases=['user'], required=True),
            password=dict(type='str', aliases=['pass', 'pwd'], required=True),
            identitygroup=dict(type='str', required=True, aliases=["group"]),
            macaddress=dict(required=False, type='list', aliases=['macs','mac']),
            ssl=dict(default=True, type='bool'),
            validate_certs=dict(default=False, type='bool'),
            force=dict(default=False, type='bool'),
            timeout=dict(default=30, type='int')
        )
    )
    
    server = module.params['host']
    port = module.params['port']
    username = module.params['username']
    password = module.params['password']
    ssl = module.params['ssl']
    identitygroup = module.params['identitygroup']
    validate_certs = module.params['validate_certs']
    macaddress_list = module.params['macaddress']
    force = module.params['force']
    timeout = module.params['timeout']
    
    try:
        group_id = get_group_id(identitygroup)
        if not group_id:
            module.fail_json(msg="Identitygroup not found on ISE, Group: '%s'" % identitygroup)
        group_endpoints = get_endpoints_by_group(group_id)
    
        if not macaddress_list or (len(macaddress_list) == 1 and macaddress_list[0] == ""):
            if not force:
                module.fail_json(msg="MAC Address List is empty, but force is disabled")
            elif len(group_endpoints) > 0:
                endpoint_id_list = []
                for ep in group_endpoints.values():
                    endpoint_id_list.append(ep.uuid)
                if not delete_endpoint_bulk(endpoint_id_list):
                    module.fail_json(msg="Deleting all Endpoints for Identitygroup: '%s' failed." % identitygroup)
                else: 
                    module.exit_json(changed=True, change_count=change_count, failed_macs=failed_macs, del_count = del_count,
                                     meta="Deleted all " + str(del_count) + " Endpoint(s) for Identitygroup: '%s'" % identitygroup)
            else: 
                module.exit_json(changed=False, failed_macs = failed_macs, change_count = 0, del_count = 0,
                                 meta="Nothing to do for Identitygroup: '%s'" % identitygroup ) 
                
        else:
            [delta_list, remove_list] = delta_mac_list(macaddress_list, group_endpoints)
            if not delta_list and not remove_list:
                module.exit_json(failed_macs = failed_macs, change_count = 0, changed = False, del_count = del_count,
                                 meta="Nothing to do for Identitygroup: '%s'" % identitygroup )
            
            # delete endpoints not in maclist but on ISE in given Identitygroup
            if remove_list:
                endpoint_id_list = []
                for ep in remove_list.values():
                    endpoint_id_list.append(ep.uuid)
                delete_endpoint_bulk(endpoint_id_list)
                if not delta_list:
                    if len(failed_macs) > 0:
                        module.fail_json(failed_macs= failed_macs,
                                         msg="Failed to delete some Endpoints not found in given MAC List.")
                    module.exit_json(failed_macs = failed_macs, change_count = 0, changed = True, del_count = del_count,
                                     meta="Removed : #" + str(del_count) + " Endpoints from Identitygroup: '%s'" % identitygroup)
                                     
                    
            if put_endpoint_bulk(delta_list):
                if len(failed_macs) == 0:
                    module.exit_json(changed=True, failed_macs = failed_macs, change_count = change_count, del_count = del_count,
                                     meta="Created or changed: " + str(change_count) + ", deleted: " + str(del_count) + " Endpoint(s) at Identitygroup: '%s'" % identitygroup)
                else:
                    module.fail_json(msg="Bulk Submit failed. Variable 'failed_macs' for more details. ", failed_macs = failed_macs )
            else:
                module.fail_json(msg="Adding Endpoints failed, maybe timeout")
                          
    
    except URLError as ex:
        module.fail_json(msg="HTTP Connection Error. HTTP Code: " + str(ex.code) + ", Status: " + ex.msg)
    except Exception as ex:
        module.fail_json(msg="Undefined Error: " + str(ex))
        
    module.exit_json(changed=False, meta=len(group_endpoints))
    

if __name__ == '__main__':
    main()