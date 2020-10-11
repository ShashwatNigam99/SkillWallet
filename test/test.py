# ! /usr/bin/env python3


import base64
import sys

from protobuf import digital_id_pb2
from protobuf.shared_id_pb2 import ShareIDTransaction, ShareIdRequest

sys.path.append('/home/suchira/digital-id/')
from protobuf.digital_id_transaction_pb2 import DigitalIdTransaction
import datetime
import os
import time


def main():
    msg = base64.b64decode('CioaKGQ2NjA5NzY3NjVlMjUzOGE4NTdiODlhMmRlZDZlY2RkNTFlNTMxOWISCklEX3JlcXVlc3Q=')
    share_ID_transaction = ShareIDTransaction()
    shared_ID_request = ShareIdRequest()
    share_ID_transaction.ParseFromString(msg)
    shared_ID_request.ParseFromString(share_ID_transaction.payload)
    print(shared_ID_request.ID_hash_requested)
    contract_b = b'\n\x15\n\x02\x08\x012\x0f\n\teducation\x12\x02\x08\x01\x10\x01\x1a\x1a2020-05-25T21:00:11.458955'
    # digital_id_transaction = DigitalIdTransaction()
    # digital_id_transaction.ParseFromString(msg)
    # pii_credential_msg = digital_id_pb2.DigitalId()
    # pii_credential_msg.ParseFromString(digital_id_transaction.digital_id)
    # print(pii_credential_msg.attribute_set.date_of_birth)
    #
    # removal_list_str = input('Please enter comma separated list of attribute to remove: ')
    # removal_list = removal_list_str.split(",")
    # print(type(removal_list))

    # start_time = time.time()  # seconds since epoch
    # # 1570034219.8407047
    # print(start_time)
    #
    # cur_time = datetime.datetime.now()
    # time_info = datetime.datetime.timestamp(cur_time)
    # print(time_info)
    # print(cur_time)

    # processed = []
    # for animal in animals:
    #     print(animal)
    #     processed.append(animal)
    #
    # print(processed)
    # animals = [x for x in animals if x not in processed]

    # print(animals)
    # key_dict = {1: ['a', 'c', 'b'], 2: ['b', 'd']}
    # k = 1
    # while k < 4:
    #     if key_dict.get(k) is None:
    #         print(k)
    #         key_dict[k] = ['b', 'c']
    #     key_dict.get(k).remove('b')
    #     print(key_dict.get(k))
    #     k += 1
    # key_dict = {}
    # key_dict = dict.fromkeys([1, 2, 3], ['a', 'b', 'c'])
    # key_dict2 = {1: ['a', 'c', 'b'], 2: ['b', 'd']}
    # key_dict3 = {1: ['a', 'c', 'b'], 2: ['b', 'd', 'e']}
    # set(key_dict) - set(key_dict2)
    # print(set(key_dict.values()))
    # print(set(key_dict) - set(key_dict2))
    # key_dict2 = {'a': 1, 'b': 2}
    # key_dict3 = {'a': 3, 'c': 4}
    # # key_dict4 = dict.copy(key_dict2)
    # del key_dict2['a']

    # for k in key_dict3.keys():
    #     if key_dict2.get(k) is None:
    #         key_dict2[k] = key_dict3[k]
    #     else:
    #         key_dict2[k] += key_dict3[k]
    # print(len([]))
    key_dict2 = {'a': 1, 'b': 2, 'c': []}
    # key_dict1 = {'d': []}
    # dict.update(key_dict2, key_dict1)
    # key_dict2['c'].extend([3, 4])
    # list1 = key_dict2['c']
    # list1.remove(3)
    # print(key_dict2)
    # print(list1)
    # key_dict2.pop('a')
    # for k in key_dict2:
    #     print(k)
    # print(key_dict2.keys())
    # s = {'a', 'b', 'c'} - {'b', 'd', 'e'}
    # print(s)
    # l1 = {1, 2, 3}
    # # l1.clear()
    # # print(l1)
    # l2 = {1, 2}
    # # dif = l1.difference(l2)
    # # print(dif)
    # # if len(l1.difference(l2)) < 0:
    # #     print(True)
    # if l1 == l2:
    #     print(True)


if __name__ == '__main__':
    main()
