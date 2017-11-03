import requests
import sys
import hashlib
from flask import Flask
from collections import namedtuple

# Should be called:
# $ python3 chord.py m PORT_TO_LISTEN optional: HOST_TO_JOIN PORT_TO_JOIN

app = Flask(__name__)

Node = namedtuple('Node', 'id host port')
class Finger:
    def __init__(self, start, range, successor):
        self.start = start
        self.range = range
        self.successor = successor

m            = 0
self         = None
predeccessor = None
finger_table = []

def build_finger_table():
    global finger_table
    for i in range(0, m - 1):
        start = (self.id + (2 ** i)) % (2 ** m)
        f = Finger(
                start,
                range(start, (self.id + (2 ** (i + 1))) % (2 ** m)),
                None
                )
        finger_table.append(f)

    last_finger = Finger(
            self.id + (2 ** (m - 1) % (2 ** m)),
            range(self.id + (2 ** (m - 1) % (2 ** m)), self.id),
            None
            )
    finger_table.append(last_finger)

"""
I got stuck on converting the first n bit to a integer for a while. So I posted
on stack overflow asking for help. This is the code contained in one of the
answers. I DO NOT CLAIM THIS CODE! This code was writen by, and belongs to
stackoverflow user ShadowRanger (https://stackoverflow.com/users/364696).

You can find the source post here: https://stackoverflow.com/a/47086786/5843840

I have also included my own solution, which just get the modulus of the whole
hash.
"""
def bitsof(bt, nbits):
    # Directly convert enough bytes to an int to ensure you have at least as many bits
    # as needed, but no more
    neededbytes = (nbits+7)//8
    if neededbytes > len(bt):
        raise ValueError("Require {} bytes, received {}".format(neededbytes, len(bt)))
    i = int.from_bytes(bt[:neededbytes], 'big')
    # If there were a non-byte aligned number of bits requested,
    # shift off the excess from the right (which came from the last byte processed)
    if nbits % 8:
        i >>= 8 - nbits % 8
    return i
# End of not my code

def get_id(host, port):
    b_str = (host + str(port)).encode()
    # This is my solution without help:
    # digest = hashlib.sha1(b_str).hexdigest()
    # return int(digest, 16) % m
    digest = hashlib.sha1(b_str).digest()
    return bitsof(digest, m)
    # Once again: bitsof() is not my code, and I TAKE NO CREDIT FOR IT.

def request_node(action, params=None):
    resp = requests.get(
            '{}:{}/{}'.format(node.host, node.port, action),
            params=params
            )
    j = resp.json()
    return Node(
            j['id'],
            j['host'],
            j['successor']
            )

def set_node(action, node):
    d = { # TODO I can probably do this implicitly
            'id' : node.id,
            'host' : node.host,
            'successor' : node.successor
            }
    requests.post(
            '{}:{}/{}'.format(node.host, node.port, action),
            data=d
            )
    
def initialize():
    global m, port, self
    m = int(sys.argv[1])
    port = sys.argv[2]
    self = Node(
            get_id('127.0.0.1', port),
            '127.0.0.1',
            port
            )
    print(self)
    build_finger_table()
    
    if len(sys.argv) > 3:
        host_to_join = sys.argv[3]
        port_to_join = int(sys.argv[4])
        node_to_join = Node(
                get_id(host_to_join, port_to_join),
                host_to_join,
                port_to_join
                )
        join(node_to_join)
    else:
        join(None)

    for finger in finger_table:
        print(finger.__dict__)
    app.run(host='127.0.0.1', port=self.port)

def join(node):
    if node:
        init_finger_table(node)
        # TODO Maybe call update others here.
    else:
        for finger in finger_table:
            finger.successor = self
        predeccessor = self

def init_finger_table(node):
    finger_table[0].successor = request_node(
            'find_successor',
            {'id' : self.id}
            )
    predeccessor = request_node(
            'predeccessor'
            )
    set_node('predeccessor', self)
    for i in xrange(0, m - 1):
        if finger_table[i + 1].start in range(self.id, finger_table[i].node.id):
            finger_table[i + 1].node = finger_table[i].node
        else:
            finger_table[i + 1].node = request_node(
                    'find_successor',
                    {'id' : finger_table[i + 1].start}
                    )

@app.route("/")
def hello():
    return "Hello World!"

if __name__ == '__main__':
    initialize()
