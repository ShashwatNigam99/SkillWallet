#! /usr/bin/env python3
import os
import sys
import time

from bsddb3 import db
from bsddb3._pybsddb import DBNoSuchFileError, DB_SET
from bsddb3.dbobj import DBEnv
from cbor import cbor

filename = '/home/suchira/Digital-id/test/fruit'
# creating database with hash access method
# DB_RECNO
# fruitDB = db.DB()
# # fruitDB.open(filename, None, db.DB_BTREE, db.DB_CREATE) KEYS=BYTES
# # fruitDB.open(filename, None, db.DB_RECNO, db.DB_CREATE) KEYS=INT OR BYTES
# # KEYS=BYTES
# # fruitDB.open(filename, None, db.DB_HASH, db.DB_CREATE)
# fruitDB.open(filename, None, db.DB_HASH, db.DB_CREATE)
# # except DBNoSuchFileError:
# #     fruitDB.open(filename, None, db.DB_HASH, db.DB_CREATE)
# print('\t %s', db.DB_VERSION_STRING)
# # fruitDB.put("other".encode(), cbor.dumps({1: "red", 2: "yellow"}))
# fruitDB.put("guava".encode(), "green")
#
# fruitDB.close()

# pid = os.fork()

dbenv = db.DBEnv()
dbenv.set_lk_detect(db.DB_LOCK_YOUNGEST)
cwd = os.getcwd()
key_dir = os.path.join(cwd, "tmp1")
dbenv.open(key_dir, db.DB_INIT_LOCK | db.DB_CREATE | db.DB_INIT_MPOOL)
# time.sleep(4)
lockid = dbenv.lock_id()
fruitDB = db.DB(dbenv)
print("dbenv locked")
print(lockid)
print(os.getpid())

fruitDB.open(filename, None, db.DB_HASH, db.DB_CREATE)
count = 0
flag = False
while 1:
    try:
        print("count {}".format(count))
        lock = dbenv.lock_get(lockid, "rec", db.DB_LOCK_WRITE, db.DB_LOCK_NOWAIT)
        flag = True
        break
    except Exception as err:
        count = count + 1
        print(err)
        pass
if flag is True:
    print("got lock {}".format(os.getpid()))
time.sleep(8)
fruitDB.put("guava".encode(), "yellow")
fruitDB.put("papya".encode(), "green")
# if pid == 0:
#     fruitDB.put("guava".encode(), "green")
dbenv.lock_put(lock)
print("Released lock {}".format(os.getpid()))
fruitDB.close()

