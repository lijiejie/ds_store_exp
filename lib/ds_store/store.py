# -*- coding: utf-8 -*-

import struct

from . import buddy


class ILocCodec(object):

    @staticmethod
    def decode(bytesData):
        if isinstance(bytesData, bytearray):
            x, y = struct.unpack_from(b'>II', bytes(bytesData[:8]))
        else:
            x, y = struct.unpack(b'>II', bytesData[:8])
        return x, y


class DSStoreEntry(object):
    def __init__(self, filename):
        if str != bytes and type(filename) == bytes:
            filename = filename.decode('utf-8')
        self.filename = filename
        
    @classmethod
    def read(cls, block):

        nlen = block.read(b'>I')[0]
        filename = block.read(2 * nlen).decode('utf-16be')

        # Next, read the code and type
        code, typecode = block.read(b'>4s4s')

        # Finally, read the data
        if typecode == b'bool':
            block.read(b'>?')[0]
        elif typecode == b'long' or typecode == b'shor':
            block.read(b'>I')[0]
        elif typecode == b'blob':
            vlen = block.read(b'>I')[0]
            block.read(vlen)
        elif typecode == b'ustr':
            vlen = block.read(b'>I')[0]
            block.read(2 * vlen).decode('utf-16be')
        elif typecode == b'type':
            block.read(b'>4s')[0]
        elif typecode == b'comp' or typecode == b'dutc':
            block.read(b'>Q')[0]
        else:
            raise ValueError('Unknown type code "%s"' % typecode)

        return DSStoreEntry(filename)


class DSStore(object):
    def __init__(self, store):
        self._store = store
        self._superblk = self._store['DSDB']
        with self._get_block(self._superblk) as s:
            self._rootnode, self._levels, self._records, \
            self._nodes, self._page_size = s.read(b'>IIIII')
        self._min_usage = 2 * self._page_size // 3
        self._dirty = False

    @classmethod
    def open(cls, ds_store_file):
        store = buddy.Allocator.open(ds_store_file)
        return DSStore(store)

    def close(self):
        self._store.close()

    def _get_block(self, number):
        return self._store.get_block(number)

    def traverse(self):
        node = self._rootnode
        with self._get_block(node) as block:
            next_node, count = block.read(b'>II')
            if next_node:
                for n in range(count):
                    ptr = block.read(b'>I')[0]
                    for e in self._traverse(ptr):
                        yield e
                    e = DSStoreEntry.read(block)
                    yield e
                for e in self._traverse(next_node):
                    yield e
            else:
                for n in range(count):
                    e = DSStoreEntry.read(block)
                    yield e
