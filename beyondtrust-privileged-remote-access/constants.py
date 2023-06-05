""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

BASE_ENDPOINT = '/api/config/v1'
USER_ENDPOINT = '/user'
VAULT_ACCOUNT_ENDPOINT = '/vault/account'
VAULT_ACCOUNT_POLICY_ENDPOINT = '/vault/account-policy'
VAULT_ACCOUNT_GROUP_ENDPOINT = '/vault/account-group'
VAULT_ENDPOINTS_ENDPOINT = '/vault/endpoint'
VENDOR_ENDPOINT = '/vendor'
VENDOR_USER_ENDPOINT = '/vendor/{0}/user'
GROUP_POLICIES_ENDPOINT = '/group-policy'
VAULT_ACCOUNT_TYPE_MAPPING = {
    'Password': 'username_password',
    'SSH': 'ssh'
}
OPERATION_MAPPING = {
    'Check In': 'check-in',
    'Check Out': 'check-out'
}