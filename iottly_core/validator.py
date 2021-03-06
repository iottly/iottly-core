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
from bson.objectid import ObjectId

import logging
import cerberus

class SchemaDictionary(object):
    schema = {}
    validator = None
    def __init__(self, value):
        self.validator = IottlyValidators(self.schema)
        if self.validator.validate(value):
            self.value = value
        else:
            raise Exception("Wrong schema or data format: %s" % str(self.validator.errors))

    def validate(self):
        return self.validator.validate(self.value)

class IottlyValidators(cerberus.Validator):
    def _validate_unique(self, unique, field, value):
        if unique:
            if not len(set([v[unique["key"]] for v in value])) == len(value):
                self._error(field, "elements must be unique based on '%s'" % unique["key"])

    def _validate_uniquetype(self, uniquetype, field, value):
        if uniquetype:
            if not len(set([v['metadata']['type'] for v in value])) == len(value):
                self._error(field, "elements must be unique based on metadata.type")


    def _validate_type_objectid(self, value):
        if type(value) == ObjectId: 
            return True