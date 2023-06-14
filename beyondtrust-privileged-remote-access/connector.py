""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """


from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations, _check_health

logger = get_logger('beyondtrust-privileged-remote-access')


class BeyondTrustConnector(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            logger.info('execute: {0}'.format(operation))
            operation = operations.get(operation)
            if not operation:
                raise ConnectorError("Unsupported Operation: {0}".format(operation))
            return operation(config, params)
        except Exception as e:
            logger.error(e)
            raise ConnectorError(e)

    def check_health(self, config):
        config['connector_info'] = {"connector_name": self._info_json.get('name'),
                                    "connector_version": self._info_json.get('version')}
        return _check_health(config)
