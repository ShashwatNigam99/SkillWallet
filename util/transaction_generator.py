#!/usr/bin/env python3
import logging
import os
import random
import time
from sys import path

import requests
import yaml
from sawtooth_sdk.protobuf.batch_pb2 import Batch
from sawtooth_sdk.protobuf.batch_pb2 import BatchHeader
from sawtooth_sdk.protobuf.batch_pb2 import BatchList
from sawtooth_sdk.protobuf.transaction_pb2 import Transaction
from sawtooth_sdk.protobuf.transaction_pb2 import TransactionHeader

path.append(os.getcwd())
from constants import digital_id_constants
from util import hashing

LOGGER = logging.getLogger("userwallet.client.transaction_generator")
LOGGER.setLevel(logging.INFO)


class TransactionGenerator(object):

    def __init__(self, base_url, public_key, signer):

        self._client_base_url = base_url
        self._client_public_key = public_key
        self._client_signer = signer

    def make_transaction(self, family, payload, input_address_list, output_address_list, dependency_list=None):
        LOGGER.debug("Inside make_transaction")
        if dependency_list is None:
            dependency_list = []
        LOGGER.debug("inside UserWalletClient._make_transaction")
        # create a TransactionHeader. referring transaction.proto

        header = TransactionHeader(
            batcher_public_key=self._client_public_key,
            dependencies=dependency_list,
            family_name=family,
            family_version="1.0",
            inputs=input_address_list,  # in set
            outputs=output_address_list,  # out set
            nonce=random.random().hex().encode(),
            payload_sha512=hashing.hash512(payload),
            signer_public_key=self._client_public_key
        ).SerializeToString()

        # Create a Transaction from the header and payload above
        transaction = Transaction(
            header=header,
            payload=payload,
            header_signature=self._client_signer.sign(header)
        )
        return transaction

    def make_batch(self, transaction_list):
        # Create a BatchHeader from transaction_list above
        LOGGER.debug("Inside make_batch")
        batch_header = BatchHeader(
            signer_public_key=self._client_public_key,
            transaction_ids=[txn.header_signature for txn in transaction_list]
        ).SerializeToString()

        # Create Batch using the BatchHeader and transaction_list above
        batch = Batch(
            header=batch_header,
            transactions=transaction_list,
            header_signature=self._client_signer.sign(batch_header)
        )

        # Create a Batch list from batch above
        batch_list = BatchList(batches=[batch])

        return batch_list

    def wait_for_status(self, batch_id, wait, result):
        """Wait until transaction status is not PENDING (COMMITTED or error).

           'wait' is time to wait for status, in seconds.
        """
        LOGGER.debug("Inside wait_for_status")
        if wait and wait > 0:
            waited = 0
            start_time = time.time()
            while waited < wait:
                result = self.send_to_rest_api("batch_statuses?id={}&wait={}"
                                               .format(batch_id, wait))
                status = yaml.safe_load(result)['data'][0]['status']
                waited = time.time() - start_time

                if status != 'PENDING':
                    return result
            LOGGER.debug("Transaction timed out after waiting {} seconds."
                         .format(wait))
            return digital_id_constants.TRANSACTION_TIMED_OUT_ERROR
        else:
            return result

    def send_to_rest_api(self, suffix, data=None, content_type=None):
        """Send a REST command to the Validator via the REST API.
        """
        LOGGER.debug("inside send_to_rest_api")
        url = "{}/{}".format(self._client_base_url, suffix)
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
