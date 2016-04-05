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
import base64
import hashlib
import os

from datetime import datetime

from iottly_core.settings import settings

file_chunks_cache = {}


def _get_md5(path):
    contents = None
    with open(path) as f:
        contents = f.read()

    while len(contents) % 1024:
        contents += chr(0xFF)

    contents += settings.SECRET_SALT

    return hashlib.md5(contents).hexdigest()

def _get_detailed_file_list(directory, extension):
    filenames = filter(lambda f: f.endswith(extension), os.listdir(directory))
    def _build_detailed_file_obj(filename):
        path = os.path.join(directory, filename)
        return dict(
            filename=filename,
            lastmodified=datetime.fromtimestamp(os.path.getmtime(path)),
            size=os.path.getsize(path),
            md5=_get_md5(path)
            )

    files = map(_build_detailed_file_obj, filenames)
    return files

def list_firmwares(projectid):
    return _get_detailed_file_list(os.path.join(settings.FIRMWARE_DIR, str(projectid)), '.bin')

def generate_chunks_file(file_path, size, chunks_filename):
    chunks = []
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(size)
            if chunk == '':
                break
            # Padding the chunk with ones
            if len(chunk) < size:
                chunk += chr(0xFF) * (size - len(chunk))
            chunks.append(base64.b64encode(chunk))

    while len(chunks) % (1024 / size):
        chunks.append(base64.b64encode(chr(0xFF) * size))

    with open(chunks_filename, 'w') as f:
        for chunk in chunks:
            f.write(chunk + '\n')

    return chunks

def get_b64_chunks(projectid, filename, size):
    base_dir = os.path.join(settings.FIRMWARE_DIR, str(projectid))
    full_path = os.path.join(base_dir, filename)

    if not os.path.isfile(full_path):
        raise IOError("File not found: {}!".format(full_path))

    chunks_filename = '{}_{}_{}.b64'.format(str(projectid), filename, size)
    chunks = file_chunks_cache.get(chunks_filename)

    if chunks is None:
        chunks_full_path = os.path.join(base_dir, chunks_filename)
        if os.path.isfile(chunks_full_path):
            with open(chunks_full_path) as f:
                chunks = f.readlines()
        else:
            chunks = generate_chunks_file(full_path, size, chunks_full_path)
        file_chunks_cache[chunks_filename] = chunks

    return chunks
