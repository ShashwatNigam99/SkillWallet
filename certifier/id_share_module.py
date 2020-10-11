#!/usr/bin/env python3
import logging
import os
from sys import path

import yaml

path.append(os.getcwd())
from constants import digital_id_constants
from protobuf import id_attribute_pb2, digital_id_pb2
from protobuf.shared_id_pb2 import ShareIdRequest, ShareIdResponse, ShareIDTransaction
from util.transaction_generator import TransactionGenerator
from util import hashing, chain_access_util

LOGGER = logging.getLogger('certifier_wallet.client')
LOGGER.setLevel(logging.DEBUG)
FAMILY_NAME_PEER_VERIFY = 'peer_verification'
FAMILY_NAME_DIGITALID = 'digitalid'
FAMILY_NAME_CERTIFIER = 'digitalid_certifier'
FAMILY_NAME_SHAREDID = 'shared_id'


class DigitalIdSharingClass(object):
    wait_time = 10

    def __init__(self, base_url, signer, public_key, to_address):
        """
        public_key is the sender's public key
        to_address is the receiver's block-chain public address
        """
        self._public_key = public_key
        self.to_address = to_address
        self._signer = signer
        self._base_url = base_url
        self.public_address = hashing.get_pub_key_hash(self._public_key)
        self.txn_generator = TransactionGenerator(base_url=self._base_url,
                                                  public_key=self._public_key,
                                                  signer=self._signer)

    def send_id_request(self, data_mode, contract_msg=None):
        LOGGER.debug("Inside send_id_request()")
        LOGGER.debug("data_mode {}".format(data_mode))
        share_ID_transaction = ShareIDTransaction()
        shared_ID_request = ShareIdRequest()
        # shared_ID_request.ID_hash_requested_only = request_mode
        shared_ID_request.recv_id_from_address = self.to_address
        if data_mode is True:
            shared_ID_request.ID_data_requested = True
            contract_bytes = contract_msg.SerializeToString()
            shared_ID_request.contract_detail = contract_bytes
            shared_ID_request.contract_signature = self._signer.sign(hashing.get_hash_from_bytes(contract_bytes))

        # send transaction
        ID_payload = shared_ID_request.SerializeToString()
        share_ID_transaction.payload = ID_payload
        share_ID_transaction.action = digital_id_constants.SHARE_ID_REQUEST
        payload = share_ID_transaction.SerializeToString()

        # sharedid[0:6] + self.from_address [0:24] + self.to_address [0:40]
        sharing_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_SHAREDID,
                                                              pub_key_hash=self.to_address,
                                                              key=self.public_address)
        input_address_list = [sharing_state_address]
        output_address_list = [sharing_state_address]
        transaction = self.txn_generator.make_transaction(family=FAMILY_NAME_SHAREDID, payload=payload,
                                                          input_address_list=input_address_list,
                                                          output_address_list=output_address_list)
        transaction_list = [transaction]
        batch_list = self.txn_generator.make_batch(transaction_list)
        batch_id = batch_list.batches[0].header_signature

        # Send batch_list to the REST API
        result = self.txn_generator.send_to_rest_api("batches", batch_list.SerializeToString(),
                                                     'application/octet-stream')
        LOGGER.debug("Result from Rest-API {}".format(result))

        result = self.txn_generator.wait_for_status(batch_id, DigitalIdSharingClass.wait_time, result)
        LOGGER.debug(result)
        print(result)
        if result != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
            status = yaml.safe_load(result)['data'][0]['status']
            if status == 'COMMITTED':
                print("Request successfully committed")
                return True
            elif status == 'UNKNOWN':
                print("Transaction status unknown")
                return True
            else:
                print("Failed to commit request")
                return False
        else:
            return False

    def send_id_response(self, hash_only):
        share_ID_transaction = ShareIDTransaction()
        shared_ID_response = ShareIdResponse()
        self_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                           pub_key_hash=self.public_address,
                                                           key='self')
        id_state_data = chain_access_util.get_state(base_url=self._base_url, address=self_state_address)
        LOGGER.debug("Existing ID state_data : {}".format(id_state_data))
        saved_id_bytes = id_state_data['digital_id']
        # confirmation_txn = id_state_data['acting_transaction_id']
        saved_id = digital_id_pb2.DigitalId()
        saved_id.ParseFromString(saved_id_bytes)

        # if saved_id.state != id_attribute_pb2.Status.CONFIRMED:
        #     pass
        # else:
        if saved_id.status != id_attribute_pb2.Status.CONFIRMED:
            LOGGER.debug("Cannot share ID. ID state is not confirmed.")
            print("Cannot share ID. ID state is not confirmed.")

        if hash_only is False:
            pass

        # TODO comment id_info population
        # id_info = Id_info()
        # id_info.id_creating_pub_key = saved_id.id_owner_public_key
        # id_info.id_confirmation_txn = confirmation_txn

        # TODO comment digital_id_hash population
        # shared_ID_response.digital_id_hash = hashing.get_hash_from_bytes(saved_id_bytes)
        shared_ID_response.digital_signature = self._signer.sign(hashing.get_hash_from_bytes(saved_id_bytes))
        shared_ID_response.send_to_address = self.to_address

        # send transaction
        ID_payload = shared_ID_response.SerializeToString()
        share_ID_transaction.payload = ID_payload
        share_ID_transaction.action = digital_id_constants.SHARE_ID_RESPONSE
        payload = share_ID_transaction.SerializeToString()

        # sharedid[0:6] + self.from_address [0:24] + self.to_address [0:40]
        # TODO to_address => doublehash(recipient_public_key+code), 160 bit or, ripemd160(to_address_code)
        sharing_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_SHAREDID,
                                                              pub_key_hash=self.public_address,
                                                              key=self.to_address)
        LOGGER.debug("sharing_state_address {}".format(sharing_state_address))
        input_address_list = [self_state_address, sharing_state_address]
        output_address_list = [sharing_state_address]
        transaction = self.txn_generator.make_transaction(family=FAMILY_NAME_SHAREDID, payload=payload,
                                                          input_address_list=input_address_list,
                                                          output_address_list=output_address_list)
        transaction_list = [transaction]
        batch_list = self.txn_generator.make_batch(transaction_list)
        batch_id = batch_list.batches[0].header_signature

        # Send batch_list to the REST API
        result = self.txn_generator.send_to_rest_api("batches", batch_list.SerializeToString(),
                                                     'application/octet-stream')
        LOGGER.debug("Result from Rest-API {}".format(result))

        result = self.txn_generator.wait_for_status(batch_id, DigitalIdSharingClass.wait_time, result)
        LOGGER.debug(result)
        print(result)
        if result != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
            status = yaml.safe_load(result)['data'][0]['status']
            if status == 'COMMITTED':
                print("Response successfully committed")
                return True
            elif status == 'UNKNOWN':
                print("Transaction status unknown")
                return True
            else:
                print("Failed to commit response")
                return False
        else:
            return False
