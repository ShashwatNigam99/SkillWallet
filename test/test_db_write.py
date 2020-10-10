#! /usr/bin/env python3
import os
import time

from bsddb3 import db

dbenv = db.DBEnv()
dbenv.set_lk_detect(db.DB_LOCK_YOUNGEST)
cwd = os.getcwd()
key_dir = os.path.join(cwd, "tmp1")
dbenv.open(key_dir, db.DB_INIT_LOCK | db.DB_RDWRMASTER | db.DB_CREATE | db.DB_INIT_MPOOL)
lockid = dbenv.lock_id()
print("dbenv locked")
print(lockid)

filename = '/home/suchira/Digital-id/test/fruit'

fruitDB = db.DB(dbenv)
fruitDB.open(filename, None, db.DB_HASH, db.DB_RDWRMASTER)
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
# time.sleep(6)
fruitDB.put("guava".encode(), "blue")
fruitDB.put("papya".encode(), "white")
# time.sleep(4)
dbenv.lock_put(lock)
print("Released lock")
fruitDB.close()
