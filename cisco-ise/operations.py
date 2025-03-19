"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

import requests, xmltodict, logging
from connectors.core.connector import get_logger, ConnectorError
from requests_toolbelt.utils import dump

MAX_SIZE = 100
logger = get_logger('cisco-ise')


def get_config_data(config):
    ipaddr = config.get('ipaddr').strip('/')
    if not ipaddr.startswith('http') and not ipaddr.startswith('https'):
        ipaddr = "https://{0}".format(ipaddr)
    username = config.get('username', None)
    port = config.get('port', 9060)
    password = config.get('password', None)
    verify_ssl = config.get('verify', None)
    return ipaddr, username, password, port, verify_ssl


def check_response(response):
    response_status_code = response.status_code
    if response.ok:
        try:
            if 'xml' in response.headers.get('Content-Type', '').lower():
                response_json = xmltodict.parse(response.content)
            else:
                response_json = response.json()
        except:
            if response.status_code in [204, 201]:
                return response
            msg_string = "Unable to parse reply as a JSON : {text} with reason: {reason}".format(text=response.text,
                                                                                                 reason=response.reason)
            raise ConnectorError(msg_string)
        return response_json
    else:
        err_msg = 'Rest API failed with Status code: {status} and details: {detail}'.format(
            status=response_status_code,
            detail=response.text)
        logger.exception(
            'Rest API failed with Status code: {status} and details: {detail}'.format(status=response_status_code,
                                                                                      detail=response.text))
        raise ConnectorError(err_msg)


def make_rest_call(endpoint, config, headers={}, params={}, payload={}, method='GET', ers_call=False):
    ipaddr, username, password, port, verify_ssl = get_config_data(config)
    if ers_call:
        msg = 'External RESTful Services (ERS) is a REST API based on HTTPS over port 9060. Provide port number to ' \
              'use this action. '
        if not port:
            logger.exception(msg)
            raise ConnectorError(msg)

        headers.update({'accept': 'application/json'})
        url = "{0}:{1}{2}".format(ipaddr, port, endpoint)
    else:
        url = "{0}{1}".format(ipaddr, endpoint)
    auth = (username, password)

    try:
        r = requests.request(method, url, auth=auth, params=params, headers=headers, json=payload, verify=verify_ssl)
        logger.warning('REQUESTS_DUMP:\n{}'.format(dump.dump_all(r).decode('utf-8')))
    except Exception as e:
        raise ConnectorError(e)
    response = check_response(r)
    return response


def quarantine_ip(config, params):
    target_ipaddr = params.get("target_ipaddr")
    try:
        endpoint = "/ise/eps/QuarantineByIP_S/{0}".format(target_ipaddr)
        request_result = make_rest_call(endpoint, config)
        return {"request_status": "success", "result": request_result}
    except Exception as e:
        error_message = "Error quarantining IP address {}. Error message as follows:\n{}".format(target_ipaddr, str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)


def quarantine_mac(config, params):
    target_mac = params.get("target_mac")
    try:
        endpoint = "/ise/eps/QuarantineByMAC_S/{0}".format(target_mac)
        request_result = make_rest_call(endpoint, config)
        return {"request_status": "success", "result": request_result}
    except Exception as e:
        error_message = "Error quarantining MAC address {}. Error message as follows:\n{}".format(target_mac, str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)


def unquarantine_ip(config, params):
    target_ipaddr = params.get("target_ipaddr")
    try:
        endpoint = "/ise/eps/UnQuarantineByIP_S/{0}".format(target_ipaddr)
        request_result = make_rest_call(endpoint, config)
        return {"request_status": "success", "result": request_result}
    except Exception as e:
        error_message = "Error un-quarantining IP address {}. Error message as follows:\n{}".format(target_ipaddr,
                                                                                                    str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)


def unquarantine_mac(config, params):
    target_mac = params.get("target_mac")
    try:
        endpoint = "/ise/eps/UnQuarantineByMAC_S/{0}".format(target_mac)
        request_result = make_rest_call(endpoint, config)
        return {"request_status": "success", "result": request_result}
    except Exception as e:
        error_message = "Error un-quarantining MAC address {}. Error message as follows:\n{}".format(target_mac, str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)


def end_session(config, params):
    target_mac = params.get("target_mac")
    try:
        endpoint = "/ise/mnt/Session/MACAddress/{0}".format(target_mac)
        request_result = make_rest_call(endpoint, config)
        acs_server = request_result['sessionParameters']['acs_server']
        disconnect_endpoint = "/ise/mnt/CoA/Disconnect/{0}/{1}/2".format(acs_server, target_mac)
        request_result = make_rest_call(disconnect_endpoint, config)
        return {"request_status": "success", "result": request_result}
    except Exception as e:
        error_message = "Error ending session for MAC address {}. Error message as follows:\n{}".format(target_mac,
                                                                                                        str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)


def log_system_off(config, params):
    target_server = params.get("target_server")
    target_mac = params.get("target_mac")
    try:
        endpoint = "/ise/mnt/CoA/Reauth/{0}/{1}/2".format(target_server, target_mac)
        request_result = make_rest_call(endpoint, config)
        return {"request_status": "success", "result": request_result}
    except Exception as e:
        error_message = "Error logging system off. Error message as follows:\n{}".format(str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)


def list_active_sessions(config, params):
    try:
        url = "/admin/API/mnt/Session/ActiveList"
        headers = {"Accept": "application/xml"}
        request_result = make_rest_call(url, config, headers=headers)
        return {"request_status": "success", "result": request_result}
    except Exception as e:
        error_message = "Error getting active sessions list. Error message as follows:\n{}".format(str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)


def list_internal_users(config, params):
    try:
        endpoint = "/ers/config/internaluser"
        query_params = build_query_params({'size': params.get('size'), 'page': params.get('page')})
        if len(params) > 0:
            query_params.update(build_query_filters(params))
        request_result = make_rest_call(endpoint, config, params=query_params, ers_call=True)
        return request_result
    except Exception as e:
        error_message = "Error getting internal user. Error message as follows:\n{}".format(str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)


def get_user_attributes(config,params):
    try:
        user_details = list_internal_users(config, params)
        if user_details["SearchResult"]["total"] != 1:
            logger.exception("User not found")
            raise ConnectorError("User not found")
        return user_details["SearchResult"]["resources"][0]
    except Exception as e:
        error_message = "Error getting internal user. Error message as follows:\n{}".format(str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)        


def _set_internal_user_status(config, params, user_enabled):        
    try:
        url = "/ers/config/internaluser/{}"
        req_payload = {
        "InternalUser": {
            "id": "",
            "name": "",
            "enabled": True
            }
        }

        user_details = get_user_attributes(config, params)
        req_payload["InternalUser"]["id"] = user_details["id"]
        req_payload["InternalUser"]["name"] = user_details["name"]
        req_payload["InternalUser"]["enabled"] = user_enabled
        url = url.format(user_details["id"])
        return make_rest_call(url, config, payload=req_payload, method='PUT', ers_call=True)
 
    except Exception as e:
        error_message = "Error setting internal user status. Error message as follows:\n{}".format(str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)        


def enable_internal_user(config, params):
    return _set_internal_user_status(config, params, True)


def disable_internal_user(config, params):
    return _set_internal_user_status(config, params, False)


def get_internal_user_details(config, params):
    try:
        endpoint = "/ers/config/internaluser/{}".format(params.get('userid'))
        return make_rest_call(endpoint, config, ers_call=True)
    except Exception as e:
        error_message = "Error getting internal user. Error message as follows:\n{}".format(str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)


def list_guest_users(config, params):
    try:
        endpoint = "/ers/config/guestuser"
        query_params = build_query_params({'size': params.get('size'), 'page': params.get('page')})
        if len(params) > 0:
            query_params.update(build_query_filters(params))
        request_result = make_rest_call(endpoint, config, params=query_params, ers_call=True)
        return request_result
    except Exception as e:
        error_message = "Error getting guest user. Error message as follows:\n{}".format(str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)


def get_guest_user_details(config, params):
    try:
        endpoint = "/ers/config/guestuser/{}".format(params.get('userid'))
        return make_rest_call(endpoint, config, ers_call=True)
    except Exception as e:
        error_message = "Error getting guest user. Error message as follows:\n{}".format(str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)


def suspend_guest_user(config, params):
    try:
        endpoint = "/ers/config/guestuser/suspend/{}"
        user_details = get_user_attributes(config,params)
        endpoint = endpoint.format(user_details["id"])
        return make_rest_call(endpoint, config, method='PUT', ers_call=True)
    except Exception as e:
        error_message = "Error suspending guest user. Error message as follows:\n{}".format(str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)


def reinstate_guest_user(config, params):
    try:
        endpoint = "/ers/config/guestuser/reinstate/{}"
        user_details = get_user_attributes(config,params)
        endpoint = endpoint.format(user_details["id"])
        return make_rest_call(endpoint, config, method='PUT', ers_call=True)
    except Exception as e:
        error_message = "Error reinstating guest user. Error message as follows:\n{}".format(str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)


def check_health(config):
    try:
        result = list_active_sessions(config, {})
        if result: return True
    except Exception as e:
        logger.exception(e)
        raise ConnectorError(e)


def get_anc_endpoint(config, params):
    anc_id = params.get("id")
    try:
        url = "/ers/config/ancendpoint"
        if anc_id:
            url += "/{}".format(anc_id)
        query_params = build_query_params({'size': params.get('size'), 'page': params.get('page')})
        request_result = make_rest_call(url, config,params=query_params, ers_call=True)
        return request_result
    except Exception as e:
        error_message = "Error in get ANC endpoint. {}".format(str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)


def build_query_params(params):
    query_params = {}
    for key, value in params.items():
        if value:
            query_params[key] = value
    return query_params


def build_query_filters(params):
    query_filters = "first_"
    filter_exists = False
    for key, value in params.items():
        if "filter." in key and value:
            query_filters = query_filters + "&filter=" +key.split(".")[1]+ ".EQ." + value
            filter_exists = True
    if filter_exists:
        return {"filter":query_filters.replace("first_&filter=","")}
    return {}


def get_ise_endpoint(config, params):
    endpoint_id = params.get("id")
    endpoint_name = params.get("endpoint_name")
    get_endpoint_by = params.get("get_endpoint_by")
    try:
        url = "/ers/config/endpoint"
        if get_endpoint_by == 'Endpoint ID':
            url += "/{}".format(endpoint_id)
        if get_endpoint_by == 'Endpoint Name':
            url += "/name/{}".format(endpoint_name)
        query_params = build_query_params({'size': params.get('size'), 'page': params.get('page')})
        request_result = make_rest_call(url, config, params=query_params, ers_call=True)
        return request_result
    except Exception as e:
        error_message = "Error in get ISE endpoint. {}".format(str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)


def get_anc_policy(config, params):
    policy_id = params.get("id")
    policy_name = params.get("policy_name")
    get_policy_by = params.get("get_policy_by")
    try:
        url = "/ers/config/ancpolicy"
        if get_policy_by == 'Policy ID':
            url += "/{}".format(policy_id)
        if get_policy_by == 'Policy Name':
            url += "/name/{}".format(policy_name)
        query_params = build_query_params({'size': params.get('size'), 'page': params.get('page')})
        request_result = make_rest_call(url, config, params=query_params, ers_call=True)
        return request_result
    except Exception as e:
        error_message = "Error in get ANC policy. {}".format(str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)


def build_policy_payload(params):
    payload = []
    for key, value in params.items():
        payload += [{"name": key, "value": params.get(key)}]
    return payload


def revoke_assign_policy(config, params, url):
    try:
        payload = {"OperationAdditionalData": {"additionalData": []}}
        payload['OperationAdditionalData']['additionalData'].extend(build_policy_payload(params))
        headers = {'content-type': 'application/json'}

        request_result = make_rest_call(url, config, payload=payload, headers=headers, method='PUT', ers_call=True)
        return request_result
    except Exception as e:
        raise ConnectorError(e)


def assign_policy(config, params):
    apply_to = params.get('apply_to')
    params.pop('apply_to')
    try:
        url = "/ers/config/ancendpoint/apply"
        if apply_to == 'MAC Address' and 'ipAddress' in params:
            params.pop('ipAddress')
        if apply_to == 'IP Address' and 'macAddress' in params:
            params.pop('macAddress')
        request_result = revoke_assign_policy(config, params, url)
        if request_result:
            return {"request_status": "success",
                    "result": "Assigned ANC policy to {0} successfully.".format(apply_to)}
    except Exception as e:
        error_message = "Error in assign policy. {}".format(str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)


def revoke_policy(config, params):
    revoke_from = params.get('revoke_from')
    params.pop('revoke_from')
    try:
        url = "/ers/config/ancendpoint/clear"
        if revoke_from == 'MAC Address' and 'ipAddress' in params:
            params.pop('ipAddress')
        if revoke_from == 'IP Address' and 'macAddress' in params:
            params.pop('macAddress')
        request_result = revoke_assign_policy(config, params, url)
        if request_result:
            return {"request_status": "success",
                    "result": "Revoked ANC policy from {0} successfully.".format(revoke_from)}
    except Exception as e:
        error_message = "Error in revoke policy. {}".format(str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)


def create_anc_policy(config, params):
    try:
        url = "/ers/config/ancpolicy"
        headers = {'content-type': 'application/json'}
        payload = {
            "ErsAncPolicy": {
                "name": params.get('name'),
                "actions": params.get('actions')
            }
        }
        request_result = make_rest_call(url, config, payload=payload, headers=headers, method='POST', ers_call=True)
        if request_result:
            return {"request_status": "success",
                    "result": "Created {} ANC policy successfully.".format(params.get('name'))}
    except Exception as e:
        error_message = "Error in create ANC policy. {}".format(str(e))
        logger.exception(error_message)
        raise ConnectorError(error_message)


operations = {
    'quarantine_ip': quarantine_ip,
    'quarantine_mac': quarantine_mac,
    'unquarantine_ip': unquarantine_ip,
    'unquarantine_mac': unquarantine_mac,
    'end_session': end_session,
    'log_system_off': log_system_off,
    'list_active_sessions': list_active_sessions,
    'check_health': check_health,
    'get_ise_endpoint': get_ise_endpoint,
    'get_anc_endpoint': get_anc_endpoint,
    'create_anc_policy': create_anc_policy,
    'get_anc_policy': get_anc_policy,
    'assign_policy': assign_policy,
    'revoke_policy': revoke_policy,
    'list_internal_users': list_internal_users,
    'disable_internal_user': disable_internal_user,
    'enable_internal_user': enable_internal_user,
    'get_internal_user_details': get_internal_user_details,
    'list_guest_users': list_guest_users,
    'get_guest_user_details': get_guest_user_details,
    'suspend_guest_user': suspend_guest_user,
    'reinstate_guest_user': reinstate_guest_user
}


