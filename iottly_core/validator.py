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
import logging
import cerberus

class SchemaDictionary(object):
    schema = {}

    def __init__(self, value):
        v = UniqueValidator(self.schema)
        if v.validate(value):
            self.value = value
        else:
            raise Exception("Wrong schema or data format: %s" % str(v.errors))


class UniqueValidator(cerberus.Validator):
    def _validate_unique(self, unique, field, value):
        if unique:
            if not len(set([v[unique["key"]] for v in value])) == len(value):
                self._error(field, "elements must be unique based on '%s'" % unique["key"])

