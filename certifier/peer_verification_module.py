#!/usr/bin/env python3

import base64
import logging
import os
import random
from datetime import datetime

import yaml
from cbor import cbor
from sys import path
from bsddb3 import db
from sawtooth_sdk.processor.exceptions import InvalidTransaction

from util.transaction_generator import TransactionGenerator

path.append(os.getcwd())
from constants import digital_id_constants
from protobuf import id_attribute_pb2, peer_verification_pb2, digital_id_pb2
from protobuf.client_pb2 import ClientAttributes
from util import chain_access_util, hashing

LOGGER = logging.getLogger('certifier_wallet.peer_verification')
LOGGER.setLevel(logging.DEBUG)
FAMILY_NAME_PEER_VERIFY = 'peer_verification'
FAMILY_NAME_DIGITALID = 'digitalid'
FAMILY_NAME_CERTIFY = 'digitalid_certifier'


class PeerVerificationClass(object):

    def __init__(self, base_url, events_db_file, signer, public_key, score):
        self.events_db_file = events_db_file
        # self.events_db = db.DB()
        self._public_key = public_key
        self._public_address = hashing.get_pub_key_hash(public_key)
        self.trust_score = score
        self._signer = signer
        self._base_url = base_url
        self.txn_generator = TransactionGenerator(base_url=self._base_url,
                                                  public_key=self._public_key,
                                                  signer=self._signer
                                                  )

    def serve_peer_requests(self):

        """serve_peer_requests method serves pending
        incoming requests for peer ID data verification """

        LOGGER.debug("Inside serve_peer_requests")
        # read the event db
        events_db = db.DB()
        try:
            events_db.open(self.events_db_file, None, db.DB_HASH, db.DB_RDWRMASTER)
            key = "peer_verification/request"
            request_list = events_db.get(key.encode())
            # processed = []
            if request_list is not None:
                request_events = cbor.loads(request_list)
                pending_list = request_events
                LOGGER.debug(request_events)
                # Modified Mar 9: request_events is a list of transaction ids
                # for request_event in request_events:
                for txn_id in request_events:
                    # address = request_event['address']
                    # txn_id = request_event['transaction_id']
                    # peer_address = request_event['sent_from']
                    # resp = input("Process request from {}? Y/N: ".format(peer_address))
                    resp = input("Process request from transaction {}? Y/N: ".format(txn_id))
                    if resp.capitalize().strip() == 'Y':
                        try:
                            # Modified Mar 9: Definition changed -
                            # self.verify_peer_data(request_txn_id, peer_address=None)

                            # isSuccess = self.verify_peer_data(peer_address=peer_address,
                            #                                   request_txn_id=txn_id)
                            isSuccess = self.verify_peer_data(request_txn_id=txn_id)
                            if isSuccess is True:
                                pending_list.remove(txn_id)
                                print("Successfully Processed")
                        except InvalidTransaction:
                            pending_list.remove(txn_id)
                            # events_db.put(key, cbor.dumps(pending_list))
                            # events_db.close()
                            print("Invalid Transaction - Removed Request from list")
                            continue
                    else:
                        # LOGGER.debug("Request from {} skipped".format(peer_address))
                        LOGGER.debug("Request from {} skipped".format(txn_id))
                        continue
                    # request_list = [event for event in request_list if event not in processed]
                LOGGER.debug(pending_list)
                events_db.put(key.encode(), cbor.dumps(pending_list))
                events_db.close()
            else:
                print("No peer verification request pending")

        except BaseException as err:
            LOGGER.error("Error while reading event db {}".format(err))
            raise Exception(err)
        finally:
            LOGGER.debug("Inside finally")
            events_db.close()

    # Modified Mar 9: Definition changed -
    # from self.verify_peer_data(request_txn_id, peer_address)

    def verify_peer_data(self, request_txn_id):
        LOGGER.debug("inside verify_peer_data")
        # serve the requests coming from the event client in database
        # get transaction id from the event attribute
        txn_response = chain_access_util.get_transaction(base_url=self._base_url, requesting_txn_id=request_txn_id)
        try:
            txn_header = txn_response['header']
            txn_payload = txn_response['payload']
            peer_transaction = peer_verification_pb2.PeerVerificationTransaction()
            peer_transaction.ParseFromString(base64.b64decode(txn_payload))
        except BaseException as err:
            LOGGER.error("Error while reading transaction data {}".format(err))
            raise Exception("Error while reading transaction data")
        operation_type = peer_transaction.type
        LOGGER.debug("operation_type {}".format(operation_type))
        peer_request_payload = peer_transaction.payload
        # total_peer = peer_transaction.total_peer_request_count
        peer_request = peer_verification_pb2.PeerVerificationRequest()
        peer_request.ParseFromString(peer_request_payload)

        req_peer_address = peer_request.peer_address
        self_address = hashing.get_pub_key_hash(self._public_key)
        if req_peer_address != self_address:
            print("Invalid Request: Request Transaction not addressed to {}".format(self_address))
            return False

        # Modified Mar 9: Retrieving peer_address from request_txn_id header
        signer_pub_key_hex = txn_header['signer_public_key']

        if txn_header['dependencies'] is not None and \
                len(txn_header['dependencies']) == 1:
            request_txn_dependencies = txn_header['dependencies'][0]
        else:
            LOGGER.error("request_txn_id {} have invalid dependency {}".
                         format(request_txn_id, txn_header['dependencies']))
            print("Invalid transaction")
            raise InvalidTransaction("Invalid dependency found for requested transaction ID")

        peer_address = hashing.get_pub_key_hash(signer_pub_key_hex)
        peer_state_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_DIGITALID,
                                                           pub_key_hash=peer_address,
                                                           key=FAMILY_NAME_CERTIFY)
        # TODO check peer's id-creation state data and match txn id with last_acting_txn
        _state_data = chain_access_util.get_state(base_url=self._base_url, address=peer_state_address)
        try:
            dependency_txn = ""
            if operation_type == digital_id_constants.TYPE_CREDIBILITY_INC:
                dependency_txn = _state_data['user_confirmation_txn']
            elif operation_type == digital_id_constants.TYPE_ID_CREATE:
                dependency_txn = _state_data['acting_transaction_id']
                LOGGER.debug("Creation dependency {}".format(dependency_txn))
            LOGGER.debug("dependent transaction from state: {}".format(dependency_txn))
            if dependency_txn != request_txn_dependencies:
                LOGGER.error("request_txn_id {} does not have the required dependency {}".
                             format(request_txn_id, dependency_txn))
                print("Invalid Input: Transaction ID not valid")
                raise InvalidTransaction("Invalid Input: Transaction ID not valid")
        except BaseException as err:
            LOGGER.error("Error while reading state data : {}".format(err))
            print("Error while reading state data of peer")
            raise InvalidTransaction("Error while reading state data")

        # if peer_address is None:
        #     peer_address = txn_signer_address
        # else:
        #     if peer_address != txn_signer_address:
        #         LOGGER.debug(
        #             "Request transaction originating from address {} instead of {}".format(txn_signer_address,
        #                                                                                    peer_address))
        #         print("Invalid Input: Request Transaction not from peer {}".format(peer_address))
        #         return False

        digital_id = digital_id_pb2.DigitalId()
        digital_id.ParseFromString(peer_request.digital_id)

        attribute_set_msg = digital_id.attribute_set
        attribute_fields = attribute_set_msg.ListFields()
        for attribute_field in attribute_fields:
            if attribute_field[0].name != 'others':
                field_name = attribute_field[0].name
                attribute = attribute_field[1]
                data = attribute.attribute_data_enc
                attribute_data = id_attribute_pb2.AttributeData()
                attribute_data.ParseFromString(data)
                print('\n{}: {}\n'.format(field_name.capitalize(),
                                          attribute_data.value.decode("utf-8").capitalize()))
                is_valid = input('Is data valid? Y/N: ')
                if is_valid.capitalize().strip() == 'Y':
                    self._issue_certificate(attribute, attribute_data)
                elif is_valid.capitalize().strip() == 'N':
                    # invalidate data
                    attribute.status = id_attribute_pb2.Status.INVALID
                    # attribute.verification_quorum = 0
                    attribute.credibility_strength = 0
                else:
                    # attribute.verification_quorum = 0
                    attribute.credibility_strength = 0

            elif attribute_field[0].name == 'others':
                attr_map = attribute_field[1]
                for field_name in attr_map:
                    attribute = attr_map[field_name]
                    value_attr_data = attribute.attribute_data_enc
                    # TODO decrypt data here
                    attribute_data = id_attribute_pb2.AttributeData()
                    attribute_data.ParseFromString(value_attr_data)
                    print('\n{}: {}\n'.format(field_name.capitalize(),
                                              attribute_data.value.decode("utf-8").capitalize()))
                    is_valid = input('Is data valid? Y/N: ')
                    if is_valid.capitalize().strip() == 'Y':
                        self._issue_certificate(attribute, attribute_data)
                    elif is_valid.capitalize().strip() == 'N':
                        # invalidate data
                        attribute.status = id_attribute_pb2.Status.INVALID
                        # attribute.verification_quorum = 0
                        attribute.credibility_strength = 0
                    else:
                        # attribute.verification_quorum = 0
                        attribute.credibility_strength = 0

                    # attr_map[field_name] = attribute

        # digital_id.attribute_set.CopyFrom(attribute_set_msg)
        LOGGER.debug("Peer Verified Digital ID : {}".format(digital_id))
        try:
            response = self._send_peer_verification_response(peer_address=peer_address,
                                                             peer_txn_id=request_txn_id,
                                                             peer_id=digital_id,
                                                             operation_type=operation_type)
        except InvalidTransaction:
            return False
        # total_peer=total_peer)
        return response
        # if response != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
        #     return True
        # else:
        #     return False

    def _issue_certificate(self, id_attribute, attribute_data):
        LOGGER.debug("inside _issue_certificate")
        attribute_data.signer_pub_key = self._public_key
        # TODO use UTC time
        current_time = datetime.now()
        attribute_data.sign_timestamp = str(current_time.isoformat())
        attribute_data.enc_code = random.random().hex().encode()
        attribute_data_bytes = attribute_data.SerializeToString()
        id_attribute.status = id_attribute_pb2.Status.CONFIRMED
        id_attribute.attribute_data_enc = attribute_data_bytes
        id_attribute.certificate = self._signer.sign(hashing.get_hash_from_bytes(attribute_data_bytes))
        # id_attribute.verification_quorum = self.trust_score
        id_attribute.credibility_strength = self.trust_score
        LOGGER.debug('id_attribute.attribute_data_enc : {}'.format(id_attribute.attribute_data_enc))

    def _send_peer_verification_response(self, peer_address, peer_txn_id, peer_id, operation_type):
        # select the attributes of the digital_id to be sent to
        # reconstruct the id for sending to peer-verification
        transaction_list = []
        peer_id_bytes = peer_id.SerializeToString()
        # TODO compress and encrypt with digital_id owner's public key
        # send new_id to peers. construct peer_verification_request message
        peer_verification_response = peer_verification_pb2.PeerVerificationResponse()
        peer_verification_response.digital_id = peer_id_bytes
        peer_verification_response.peer_signature = self._signer.sign(hashing.get_hash_from_bytes(peer_id_bytes))

        # set client_info
        client_info = ClientAttributes()
        # TODO set client_info.user_address
        client_info.user_address = self._public_address
        client_info.trust_score = self.trust_score
        client_info.family_name = FAMILY_NAME_CERTIFY
        peer_verification_response.peer_info.CopyFrom(client_info)

        peer_response_payload = peer_verification_response.SerializeToString()

        peer_verification_transaction = peer_verification_pb2.PeerVerificationTransaction()
        peer_verification_transaction.payload = peer_response_payload
        peer_verification_transaction.action = digital_id_constants.PEER_VERIFICATION_RESPONSE
        peer_verification_transaction.type = operation_type
        # peer_verification_transaction.total_peer_request_count = total_peer
        txn_payload = peer_verification_transaction.SerializeToString()

        # set peer request transaction as dependency transaction
        dependencies = [peer_txn_id]

        # peer address: FAMILY_NAME_PEER_VERIFY[0:6] + FAMILY_NAME_DIGITALID [0:24] + owner_public_key_hash [0:40]
        quorum_address = hashing.get_digitalid_address(family_name=FAMILY_NAME_PEER_VERIFY,
                                                       pub_key_hash=peer_address,
                                                       key=FAMILY_NAME_DIGITALID)
        LOGGER.debug("quorum address {}".format(quorum_address))

        # peer_address is state address where the ID is stored
        input_address_list = [quorum_address]
        output_address_list = [quorum_address]
        transaction = self.txn_generator.make_transaction(family=FAMILY_NAME_PEER_VERIFY,
                                                          payload=txn_payload,
                                                          input_address_list=input_address_list,
                                                          output_address_list=output_address_list,
                                                          dependency_list=dependencies)
        transaction_list.append(transaction)

        batch_list = self.txn_generator.make_batch(transaction_list=transaction_list)
        batch_id = batch_list.batches[0].header_signature
        wait_time = 10
        # Send batch_list to the REST API
        response = self.txn_generator.send_to_rest_api("batches", batch_list.SerializeToString(),
                                                       'application/octet-stream')

        result = self.txn_generator.wait_for_status(batch_id, wait_time, response)
        LOGGER.debug(result)
        print(result)
        if result != digital_id_constants.TRANSACTION_TIMED_OUT_ERROR:
            status = yaml.safe_load(result)['data'][0]['status']
            if status == 'COMMITTED':
                print("Response successfully committed")
                return True
            else:
                print("Failed to commit response")
                return False
        else:
            return False
