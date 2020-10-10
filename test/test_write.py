#! /usr/bin/env python3
import os
import time

import cbor
from bsddb3 import db

# dbenv = db.DBEnv()
# dbenv.set_lk_detect(db.DB_LOCK_YOUNGEST)
# cwd = os.getcwd()
# key_dir = os.path.join(cwd, "tmp")
# dbenv.open(key_dir, db.DB_INIT_LOCK | db.DB_RDWRMASTER | db.DB_CREATE | db.DB_INIT_MPOOL)
# time.sleep(7)
# lockid = dbenv.lock_id()
# print("dbenv locked")
# print(lockid)

filename = '/home/suchira/Digital-id/test/fruit'
# filename = '/home/suchira/Digital-id/certifier_events_db'
fruitDB = db.DB()
fruitDB.open(filename, None, db.DB_HASH, db.DB_CREATE)
# count = 0
# flag = False
# while 1:
#     print("count {}".format(count))
#     try:
#         lock = dbenv.lock_get(lockid, "guava", db.DB_LOCK_WRITE, db.DB_LOCK_NOWAIT)
#         flag = True
#         break
#     except Exception as err:
#         count = count + 1
#         print(err)
#         pass
# if flag is True:
#     print("got lock {}".format(os.getpid()))
# time.sleep(6)
# dirc = [{'d': 2, 'c': 1}, {'a': 1, 'b': 2}]
# fruitDB.put(b'digitalid/request', cbor.dumps(dirc))

cursor = fruitDB.cursor()
# lock = dbenv.lock_get(lockid, "anytid", db.DB_LOCK_WRITE, db.DB_LOCK_NOWAIT)
rec = cursor.first()
while rec:
    print(rec)
    rec = cursor.next()

# dbenv.lock_put(lock)
# print("Released lock")
# fruitDB.delete(b'digitalid/request')
# fruitDB.put(b'1', b'hello')
# fruitDB.close()
# fruitDB = db.DB()
# fruitDB.open(filename, None, db.DB_HASH, db.DB_CREATE)
# fruitDB.put(b'2', b'hello')
fruitDB.close()
