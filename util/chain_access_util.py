#!/usr/bin/env python3

import base64
import logging
import os
from sys import path

import requests
import yaml
from cbor import cbor

path.append(os.getcwd())
from constants import digital_id_constants

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


def get_state(base_url, address):
    LOGGER.debug("Inside get_state")
    # result = self._send_to_rest_api("state/{}".format(address))
    suffix = "state/{}".format(address)
    url = "{}/{}".format(base_url, suffix)
    # print("Get state at URL : {} \n".format(url))
    headers = {}

    try:
        result = requests.get(url, headers=headers)

        if not result.ok:

            if result.status_code == digital_id_constants.HTTP_STATUS_404:
                LOGGER.debug(result)
                result_text = result.text
                state_error = yaml.safe_load(result_text)["error"]
                error_code = state_error['code']
                error_title = state_error['title']
                LOGGER.debug("Error: {} : {}".format(error_code, error_title))
                return error_code
            else:
                raise Exception("Error {}: {}".format(
                    result.status_code, result.reason))
    except requests.ConnectionError as err:
        raise Exception(
            'Failed to connect to {}: {}'.format(url, str(err)))
    except BaseException as err:
        raise Exception(err)

    LOGGER.debug(result)
    result_text = result.text

    try:
        state_data = cbor.loads(base64.b64decode(yaml.safe_load(result_text)["data"]))
        LOGGER.debug(state_data)
        return state_data
    except BaseException:
        raise Exception("State data response cannot be read")


def get_transaction(base_url, requesting_txn_id):
    LOGGER.debug("Inside get_transaction()")
    suffix = "transactions/{}".format(requesting_txn_id)
    response = send_to_rest_api(base_url=base_url, suffix=suffix)
    LOGGER.debug("GET response for transaction id {} : {}".format(requesting_txn_id, response))
    try:
        txn_response = yaml.safe_load(response)["data"]
        LOGGER.debug("get_transaction response: {}".format(txn_response))
        return txn_response
    except BaseException:
        LOGGER.error("Requesting transaction {} cannot be retrieved".format(requesting_txn_id))
        raise Exception("Transaction dependency not valid")


def send_to_rest_api(base_url, suffix, data=None, content_type=None):
    """Send a REST command to the Validator via the REST API.
    """
    LOGGER.debug("send_to_rest_api")
    url = "{}/{}".format(base_url, suffix)
    print("URL to send to REST API is {}".format(url))

    headers = {}

    if content_type is not None:
        headers['Content-Type'] = content_type

    try:
        if data is not None:
            result = requests.post(url, headers=headers, data=data)
        else:
            result = requests.get(url, headers=headers)

        if not result.ok:
            raise Exception("Error {}: {}".format(
                result.status_code, result.reason))
    except requests.ConnectionError as err:
        raise Exception(
            'Failed to connect to {}: {}'.format(url, str(err)))
    except BaseException as err:
        raise Exception(err)

    return result.text
