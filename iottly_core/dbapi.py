"""

Copyright 2015 Stefano Terna

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""
from tornado import gen
from bson.objectid import ObjectId
import motor

from iottly_core.settings import settings

db = motor.MotorClient(settings.MONGO_DB_URL)[settings.MONGO_DB_NAME]


@gen.coroutine
def insert(collection_name, data):
    if data is None or len(data) == 0:
        return

    new_id = yield db[collection_name].insert(data)
    raise gen.Return(new_id)

@gen.coroutine
def remove_by_id(collection_name, _id):
    result = yield db[collection_name].remove({"_id": ObjectId(_id)})    
    raise gen.Return(result)


@gen.coroutine
def find_one_by_id(collection_name, _id):
    result = yield db[collection_name].find_one({"_id": ObjectId(_id)})
    raise gen.Return(result)


@gen.coroutine
def find_all(collection_name, sort, limit):
    cursor = db[collection_name].find()

    results = []

    # Modify the query before iterating
    cursor.sort(sort).limit(limit)
    while (yield cursor.fetch_next):
        results.append(cursor.next_object())

    raise gen.Return(results)

@gen.coroutine
def find_one_array_by_condition(collection_name, arrayname, condition):
    result = yield db[collection_name].find_one(
        condition, 
        { "{}.$".format(arrayname): 1 })
    if arrayname in result and len(result[arrayname]) > 0:
        result = result[arrayname][0]
    else: 
        result = None

    raise gen.Return(result)


@gen.coroutine
def update_by_id(collection_name, _id, document, filter=None):
    search = {"_id": ObjectId(_id)}
    if filter:
        search.update(filter)

    result = yield db[collection_name].update(search,
                                             {"$set": document})
    raise gen.Return(result)


