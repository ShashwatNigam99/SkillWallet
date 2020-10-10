#! /usr/bin/env python3
import os

import cbor
from bsddb3 import db

# dbenv = db.DBEnv()
# dbenv.set_lk_detect(db.DB_LOCK_YOUNGEST)
# cwd = os.getcwd()
# key_dir = os.path.join(cwd, "tmp")
# dbenv.open(key_dir, db.DB_INIT_LOCK | db.DB_RDWRMASTER | db.DB_CREATE | db.DB_INIT_MPOOL)
# lockid = dbenv.lock_id()
# print("dbenv locked")
# print(lockid)
# filename = '/home/suchira/Digital-id/certifier1/certifier_events_db'
# filename = '/home/suchira/Digital-id/user03/user_wallet_db'
filename = '/home/suchira/Digital-id/user_registry_db'
fruitDB = db.DB()
# fruitDB.open(filename, None, db.DB_HASH, db.DB_DIRTY_READ)
# fruitDB.open(filename, None, db.DB_HASH, db.DB_RDONLY)
fruitDB.open(filename, None, db.DB_HASH, db.DB_RDWRMASTER)
cursor = fruitDB.cursor()
# lock = dbenv.lock_get(lockid, "anytid", db.DB_LOCK_WRITE, db.DB_LOCK_NOWAIT)
# rec = cursor.first()
# while rec:
#     print(rec)
#     rec = cursor.next()

# dbenv.lock_put(lock)

# fruitDB.delete(b'digitalid/invalidate')
# fruitDB.put(b'black_list', cbor.dumps(['492f9b187a9c24bc78cb4347c809c13e55612e00',
#                                       'e8e31637829ce3a9189dfaa9f0352fd6559007e3']))
# fruitDB.get(b'black_list')
# fruitDB.put(b'black_list', cbor.dumps([]))

# key = 'digitalid/invalidate'
# txn = 'cff310a6d66cbbf2cf405692c88895da48e49ff2b04895108079f45c4015f5497fb95b48f5a4d0058b4df089dc56e7c53fa2026949c5f17c0548ea3c4e8d060d'
# request_list = cbor.loads(fruitDB.get(b'digitalid/invalidate'))
# request_list.remove(txn)
# fruitDB.put(key.encode(), cbor.dumps(request_list))

# print(cbor.loads(fruitDB.get(b'black_list')))
# print(int.from_bytes(fruitDB.get(b'767c5493b5283b78ac1452fdfa739636cb635f10'), byteorder='big'))

# '310750decee6ecc9773f6685e23417459153ccdea03b7aeb48daf4df27fb223870c3a2fa3a64e0bb19285717840233ca28a9e3310f8693495dbf7dab7328e40a
# 19 May: old value ['492f9b187a9c24bc78cb4347c809c13e55612e00', 'e8e31637829ce3a9189dfaa9f0352fd6559007e3']
print(cbor.loads(fruitDB.get(b'black_list')))

fruitDB.close()
