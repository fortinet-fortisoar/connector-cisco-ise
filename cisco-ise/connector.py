"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

from connectors.core.connector import Connector
from connectors.core.connector import get_logger, ConnectorError
from .operations import operations

logger = get_logger('cisco-ise')


class Cisco_ise(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            logger.info("operation: {}".format(operation))
            action = operations.get(operation)
            result = action(config, params)
            return result
        except Exception as e:
            error_message = "Error in execute(). Error message as follows: {0}".format(str(e))
            logger.exception(error_message)
            raise ConnectorError(error_message)

    def check_health(self, config):
        try:
            healthy = operations.get("check_health")(config)
            return healthy
        except Exception as e:
            error_message = "Error in Health check. Error message as follows: {0}".format(str(e))
            logger.exception(error_message)
            raise ConnectorError(error_message)
