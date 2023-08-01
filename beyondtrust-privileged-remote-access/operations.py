""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests
from requests.auth import HTTPBasicAuth
import json
from datetime import datetime
from connectors.core.utils import update_connnector_config
from time import time, ctime
from connectors.core.connector import ConnectorError, get_logger
from .constants import *

logger = get_logger('beyondtrust-privileged-remote-access')


class BeyondTrust(object):
    def __init__(self, config):
        self._server_url = config.get('host', '').strip('/')
        if not self._server_url.startswith('https://') and not self._server_url.startswith('http://'):
            self._server_url = 'https://' + self._server_url
        self.client_id = config.get('client_id')
        self.client_secret = config.get('client_secret')
        self._verify_ssl = config.get('verify_ssl')
        self._token = self.validate_token(config)  # if config.get('access_token') else None

    def make_rest_call(self, method, endpoint, data=None, params=None, headers=None):
        try:
            service_endpoint = '{0}{1}{2}'.format(self._server_url, BASE_ENDPOINT, endpoint)
            logger.info("Service URL: {0}".format(service_endpoint))
            headers = {
                'Authorization': self._token
            }
            if method in ['GET', 'DELETE']:
                headers['Accept'] = 'application/json'
            else:
                headers['Content-Type'] = 'application/json'
            response = requests.request(method, service_endpoint, headers=headers,
                                        data=json.dumps(data) if data else None, params=params, verify=self._verify_ssl)
            try:
                from connectors.debug_utils.curl_script import make_curl
                make_curl(method, endpoint, headers=headers, params=params, data=data, verify_ssl=self.verify_ssl)
            except Exception as err:
                logger.error(f"Error in curl utils: {str(err)}")
            logger.debug("API Response Status Code: {0}".format(response.status_code))
            logger.debug("API Response: {0}".format(response.text))
            if response.ok:
                if not response.text:
                    return {'status_code': response.status_code}
                return response.json()
            else:
                logger.error("{0}".format(response.text))
                raise ConnectorError("{0}".format(response.text))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            logger.error(err)
            raise ConnectorError(err)

    def convert_ts_epoch(self, ts):
        try:
            datetime_object = datetime.strptime(ctime(ts), '%a %b %d %H:%M:%S %Y')
        except:
            datetime_object = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S.%f')

        return datetime_object.timestamp()

    def validate_token(self, connector_config):
        ts_now = time()
        if not connector_config.get('access_token'):
            logger.error('Error occurred while connecting server: Unauthorized')
            raise ConnectorError('Error occurred while connecting server: Unauthorized')
        expires = connector_config['expires_in']
        expires_ts = self.convert_ts_epoch(expires)
        if ts_now > float(expires_ts):
            connector_info = connector_config.get('connector_info')
            logger.debug("Token expired at {0}".format(expires))
            token_resp = generate_token(connector_config)
            connector_config['access_token'] = token_resp['access_token']
            connector_config['expires_in'] = token_resp['expires_in']
            update_connnector_config(connector_info['connector_name'], connector_info['connector_version'],
                                     connector_config,
                                     connector_config['config_id'])
            return "Bearer {0}".format(connector_config.get('access_token'))
        else:
            logger.debug("Token is valid till {0}".format(expires))

            return "Bearer {0}".format(connector_config.get('access_token'))


def generate_token(config):
    try:
        url = "{0}/oauth2/token".format(config['host'])
        payload = {
            "grant_type": "client_credentials"
        }
        headers = {
            'Content-Type': 'application/json'
        }
        response = requests.request(method='POST', url=url, data=json.dumps(payload), headers=headers,
                                    verify=config['verify_ssl'],
                                    auth=HTTPBasicAuth(config['client_id'], config['client_secret']))
        if response.ok:
            ts_now = time()
            token_resp = response.json()
            token_resp['expires_in'] = (ts_now + token_resp['expires_in']) if token_resp.get("expires_in") else None
            return token_resp
        raise ConnectorError("{0}".format(response.json()['message']))
    except Exception as Err:
        raise ConnectorError(Err)


def _check_health(config):
    try:
        connector_info = config.get('connector_info')
        if 'access_token' not in config:
            token_resp = generate_token(config)
            logger.info('connector available')
            config['access_token'] = token_resp.get('access_token')
            config['expires_in'] = token_resp.get('expires_in')
            update_connnector_config(connector_info['connector_name'], connector_info['connector_version'], config,
                                     config['config_id'])
            return True
        else:
            BeyondTrust(config)
            logger.info('connector available')
            return True
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


def build_payload(params={}, bool_to_str=True):
    payload = {}
    for k, v in params.items():
        if type(v) is dict:
            payload[k] = build_payload(v)
        elif type(v) is bool and bool_to_str:
            payload[k] = 'true' if v else 'false'
        elif isinstance(v, (bool, int)) or v:
            payload[k] = v
    return payload


def get_all_users(config, params):
    bt = BeyondTrust(config)
    params_dict = build_payload(params)
    response = bt.make_rest_call(method='GET', endpoint=USER_ENDPOINT, params=params_dict)
    return response


def get_all_accounts_in_vault(config, params):
    bt = BeyondTrust(config)
    account_type = params.get('type')
    params['type'] = VAULT_ACCOUNT_TYPE_MAPPING.get(account_type, account_type)
    params_dict = build_payload(params)
    response = bt.make_rest_call(method='GET', endpoint=VAULT_ACCOUNT_ENDPOINT, params=params_dict)
    return response


def create_account_in_vault(config, params):
    bt = BeyondTrust(config)
    account_type = params.get('type')
    params['type'] = VAULT_ACCOUNT_TYPE_MAPPING.get(account_type, account_type)
    payload = build_payload(params)
    if payload['type'] == 'ssh':
        payload['private_key_passphrase'] = params.get('private_key_passphrase')
    response = bt.make_rest_call(method='POST', endpoint=VAULT_ACCOUNT_ENDPOINT, data=payload)
    return response


def delete_account_in_vault(config, params):
    bt = BeyondTrust(config)
    endpoint = '{0}/{1}'.format(VAULT_ACCOUNT_ENDPOINT, params.get('account_id'))
    response = bt.make_rest_call(method='DELETE', endpoint=endpoint)
    response['message'] = 'Account deleted successfully.'
    return response


def checkin_or_checkout_private_key_or_password(config, params):
    bt = BeyondTrust(config)
    operation = OPERATION_MAPPING.get(params.get('operation'))
    endpoint = '{0}/{1}/{2}'.format(VAULT_ACCOUNT_ENDPOINT, params.get('account_id'), operation)
    response = bt.make_rest_call(method='POST', endpoint=endpoint)
    if operation == 'check-in':
        return {"message": "checked in successfully."}
    return response


def get_all_vault_endpoints(config, params):
    bt = BeyondTrust(config)
    params_dict = build_payload(params)
    response = bt.make_rest_call(method='GET', endpoint=VAULT_ENDPOINTS_ENDPOINT, params=params_dict)
    return response


def get_all_vendor_groups(config, params):
    bt = BeyondTrust(config)
    endpoint = VENDOR_ENDPOINT
    group_id = params.pop('group_id', '')
    if group_id or group_id == 0:
        endpoint += '/{0}'.format(group_id)
    params_dict = build_payload(params)
    response = bt.make_rest_call(method='GET', endpoint=endpoint, params=params_dict)
    return response


def create_or_update_vendor_group(config, params):
    bt = BeyondTrust(config)
    endpoint = VENDOR_ENDPOINT
    group_id = params.pop('group_id', '')
    method = 'POST'
    if group_id or group_id == 0:
        endpoint += '/{0}'.format(group_id)
        method = 'PATCH'
    payload = {
        "name": params.get("name"),
        "default_policy": params.get("default_policy"),
        "account_expiration": params.get("account_expiration"),
        "user_added_notification_enabled": params.get("user_added_notification_enabled", True),
        "user_expired_notification_enabled": params.get("user_expired_notification_enabled", True),
        "user_approval_enabled": params.get("user_approval_enabled", False),
        "user_reactivation_enabled": params.get("user_reactivation_enabled", False),
        "administrator_id": params.get("administrator_id"),
        "network_restrictions": params.get("network_restrictions").split(',') if params.get("network_restrictions") else []
    }
    payload = build_payload(payload, False)
    response = bt.make_rest_call(method=method, endpoint=endpoint, data=payload)
    return response


def delete_vendor_group(config, params):
    bt = BeyondTrust(config)
    endpoint = VENDOR_ENDPOINT + '/{0}'.format(params.get('group_id'))
    response = bt.make_rest_call(method='DELETE', endpoint=endpoint)
    response["message"] = "Vendor group deleted successfully."
    return response


def get_all_users_in_vendor_group(config, params):
    bt = BeyondTrust(config)
    endpoint = VENDOR_USER_ENDPOINT.format(params.pop('group_id'))
    user_id = params.get('user_id')
    if user_id or user_id == 0:
        endpoint += '/{0}'.format(user_id)
    params_dict = build_payload(params)
    response = bt.make_rest_call(method='GET', endpoint=endpoint, params=params_dict)
    return response


def create_user_in_vendor_group(config, params):
    bt = BeyondTrust(config)
    endpoint = VENDOR_USER_ENDPOINT.format(params.pop('group_id'))
    payload = {
      "username": params.get("username"),
      "public_display_name": params.get("public_display_name"),
      "password": params.get("password"),
      "password_expiration": None if params.get('password_never_expire') else handle_date(params.get("password_expiration")),
      "password_reset_next_login": params.get("password_reset_next_login"),
      "account_disabled": params.get("account_disabled"),
      "email_address": params.get("email_address"),
      "preferred_email_language": params.get("preferred_email_language")
    }
    payload = build_payload(payload, bool_to_str=False)
    response = bt.make_rest_call(method='POST', endpoint=endpoint, data=payload)
    return response


def remove_user_from_vendor_group(config, params):
    bt = BeyondTrust(config)
    user_id = params.get('user_id')
    endpoint = VENDOR_USER_ENDPOINT.format(params.pop('group_id')) + '/{0}'.format(user_id)
    response = bt.make_rest_call(method='DELETE', endpoint=endpoint)
    response["message"] = "User removed successfully."
    return response


def handle_date(str_date):
    return datetime.strptime(str_date, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%dT%H:%M:%S+00:00")


def get_all_group_policies(config, params):
    bt = BeyondTrust(config)
    params_dict = build_payload(params)
    response = bt.make_rest_call(method='GET', endpoint=GROUP_POLICIES_ENDPOINT, params=params_dict)
    return response


def get_all_account_policies_and_group(config, params, endpoint):
    bt = BeyondTrust(config)
    params_dict = build_payload(params)
    response = bt.make_rest_call(method='GET', endpoint=endpoint, params=params_dict)
    return response


def get_all_vault_account_policies(config, params):
    return get_all_account_policies_and_group(config, params, VAULT_ACCOUNT_POLICY_ENDPOINT)


def get_all_vault_account_groups(config, params):
    return get_all_account_policies_and_group(config, params, VAULT_ACCOUNT_GROUP_ENDPOINT)


operations = {
    'get_all_users': get_all_users,
    'get_all_accounts_in_vault': get_all_accounts_in_vault,
    'create_account_in_vault': create_account_in_vault,
    'delete_account_in_vault': delete_account_in_vault,
    'get_all_vault_account_policies': get_all_vault_account_policies,
    'get_all_vault_account_groups': get_all_vault_account_groups,
    'checkin_or_checkout_private_key_or_password': checkin_or_checkout_private_key_or_password,
    'get_all_vault_endpoints': get_all_vault_endpoints,
    'get_all_vendor_groups': get_all_vendor_groups,
    'create_vendor_group': create_or_update_vendor_group,
    'update_vendor_group': create_or_update_vendor_group,
    'get_vendor_group_by_id': get_all_vendor_groups,
    'delete_vendor_group': delete_vendor_group,
    'get_all_users_in_vendor_groups': get_all_users_in_vendor_group,
    'get_user_in_vendor_groups': get_all_users_in_vendor_group,
    'create_user_in_vendor_group': create_user_in_vendor_group,
    'remove_user_from_vendor_groups': remove_user_from_vendor_group,
    'get_all_group_policies': get_all_group_policies,
}
