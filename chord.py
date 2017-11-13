import requests
import sys
import json
import hashlib
import logging
from flask import Flask, request, jsonify
from collections import namedtuple
from threading import Thread
from time import sleep
from random import randint

# Should be called:
# $ python3 chord.py m PORT_TO_LISTEN optional: HOST_TO_JOIN PORT_TO_JOIN

app = Flask(__name__)

Node = namedtuple('Node', 'id host port')


class Finger:
    """
    Finger class, used for finger table entries.
    I would have prefered to use a named tuple here, but we need to change the
    successor sometimes. For logging, I find `.__dict__` to be useful.

    Params:
        start (int): The start value of that finger entry.
        range (range | list): The range of values in this entry.
        successor (Node): The Node holding this entry.
    """
    def __init__(self, start, range, successor):
        self.start = start
        self.range = range
        self.successor = successor


class MaintenanceThread(Thread):
    def __init__(self):
        Thread.__init__(self)

    def run(self):
        delay = 30
        while True:
            sleep(delay)
            log.info('stabilizing')
            stabilize()
            fix_fingers()
            log.debug('Finger Table:')
            for finger in finger_table:
                log.debug(finger.__dict__)


m            = 0
self         = None
predeccessor = None
finger_table = []


def chord_range(*args):
    """
    Returns a list containing a looping range, as required by chord.
    For example:
        if m=3, then:
        chord_range(5, 2) would return:
        [5, 6, 7, 0, 1]
    Params:
        1 param will return chord_range(0, arg).
        2 params will result in the above example.
        all following params will be ignored.
    """
    log.debug('chord_range() called on: {}'.format(args))
    if args[1] is not None:
        min = args[0]
        max = args[1]
    else:
        min = 0
        max = args[1]
    loop = 2 ** m
    if max < loop and max > min:
        return list(range(min, max))
    elif min > loop:
        return []
    else:
        return list(range(min, loop)) + list(range(0, max))


log = logging.getLogger('chord')
logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S')
log.setLevel(logging.DEBUG)


def build_finger_table():
    global finger_table
    for i in range(m - 1):
        start = (self.id + (2 ** i)) % (2 ** m)
        f = Finger(
                start,
                range(start, (self.id + (2 ** (i + 1))) % (2 ** m)),
                None
                )
        finger_table.append(f)

    last_finger = Finger(
            (self.id + (2 ** (m - 1))) % (2 ** m),
            range((self.id + (2 ** (m - 1))) % (2 ** m), self.id),
            None
            )
    finger_table.append(last_finger)
    log.debug('Finger table built.')


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


def dump_info():
    print({
            'id': self.id,
            'successor': finger_table[0].successor.id,
            'predeccessor': predeccessor.id
            })
    log.debug('Finger table:')
    for finger in finger_table:
        log.debug(finger.__dict__)


def get_id(host, port):
    b_str = (host + str(port)).encode()
    # This is my solution without help:
    # digest = hashlib.sha1(b_str).hexdigest()
    # return int(digest, 16) % m
    digest = hashlib.sha1(b_str).digest()
    return bitsof(digest, m)
    # Once again: bitsof() is not my code, and I TAKE NO CREDIT FOR IT.


def request_node(node, action, params=None):
    log.info('requesting node from http://{}:{}/{}'.format(node.host, node.port, action))
    resp = requests.get(
            'http://{}:{}/{}'.format(node.host, node.port, action),
            params=params
            )
    j = resp.json()
    return Node(
            j['id'],
            j['host'],
            j['port']
            )


def set_node(node, action, node_to_set):
    d = { # TODO I can probably do this implicitly
            'id': node_to_set.id,
            'host': node_to_set.host,
            'port': node_to_set.port
            }
    log.info('posting {} to http://{}:{}/{}'.format(
        d,
        node.host,
        node.port,
        action
        )
        )
    r = requests.post(
            'http://{}:{}/{}'.format(node.host, node.port, action),
            data=d
            )
    log.debug('post request returned status code: {}'.format(r.status_code))


def initialize():
    global m, port, self
    m = int(sys.argv[1])
    port = sys.argv[2]
    self = Node(
            get_id('127.0.0.1', port),
            '127.0.0.1',
            port
            )
    log.info('initialized self as {}'.format(self))
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

    log.info('Finger Table after initialization:')
    for finger in finger_table:
        log.info(finger.__dict__)

    MaintenanceThread().start()
    app.run(host='127.0.0.1', port=self.port)


def join(node):
    log.debug('join() called')
    global finger_table, predeccessor
    if node:
        log.debug('About to init finger table')
        init_finger_table(node)
        # TODO Maybe call update others here.
    else:
        for finger in finger_table:
            finger.successor = self
        predeccessor = self
    log.debug('join() done, predeccessor = {}'.format(predeccessor))
    dump_info()


def init_finger_table(node):
    global finger_table, predeccessor
    finger_table[0].successor = request_node(
            node,
            'find_successor',
            {'id': self.id}
            )
    log.info('successor = {}'.format(finger_table[0].successor._asdict()))
    predeccessor = request_node(
            finger_table[0].successor,
            'predeccessor'
            )
    set_node(node, 'predeccessor', self)
    for i in range(0, m - 1):
        log.debug('made finger {}'.format(finger_table[i].__dict__))
        if finger_table[i + 1].start in chord_range(self.id, finger_table[i].successor.id):
            finger_table[i + 1].successor = finger_table[i].successor
        else:
            finger_table[i + 1].successor = request_node(
                    node, 
                    'find_successor',
                    {'id': finger_table[i + 1].start}
                    )
    log.info('Finger table initialized')
    dump_info()


def check_predeccessor():
    global finger_table
    log.debug('check_predeccessor called')
    if finger_table[0].successor == self:
        # This is just so we don't waste time makign a request to ourselves.
        x = predeccessor
    else:
        x = request_node(
                finger_table[0].successor,
                'predeccessor'
                )
    log.debug('potential successor = {}'.format(x))
    if (self.id == finger_table[0].successor.id):
        finger_table[0].successor = x
    elif (
            x.id + 1 != finger_table[0].successor.id and
            x.id in chord_range(self.id + 1, finger_table[0].successor.id)
        ):
        log.debug('Node {} is within {}'.format(x.id, chord_range(self.id + 1, finger_table[0].successor.id)))
        finger_table[0].successor = x
        log.info('New successor: {}'.format(x.id))
        # check_predeccessor()
        """
        That last line in not in the original spec, but it covers the case
        where multiple nodes have joined between us and out successor. Which
        seems like it may happen, and it only adds constant time.
        """
    else:
        log.debug('Predeccessor was not changed.')
    dump_info()


def stabilize():
    log.info('stablize() called')
    check_predeccessor()
    set_node(
            finger_table[0].successor,
            'notify',
            self
            )
    dump_info()


def fix_fingers():
    i = randint(1, m - 1)
    log.info('Fixing finger {}'.format(finger_table[i].__dict__))
    finger_table[i].successor = _find_successor(finger_table[i].start)
    log.info('Finger is now {}'.format(finger_table[i].__dict__))


def _closest_preceding_finger(key):
    for finger in reversed(finger_table):
        if finger.successor.id in chord_range(self.id + 1, key):
            return finger.successor
    return self


def _find_successor(key):
    log.info('lookfing for successor of {}'.format(key))
    pred = _find_predeccessor(key)
    if pred == self:
        succ = finger_table[0].successor
        log.info('successor found: {}'.format(succ))
        return succ
    else:
        succ = request_node(
                pred,
                'successor'
                )
        log.info('successor found: {}'.format(succ.id))
        return succ


def _find_predeccessor(key):
    log.info('find_predeccessor() called for key {}'.format(key))
    #if key in chord_range(self.id + 1, finger_table[0].successor.id + 1):
        #log.info('found predeccessor {}'.format(finger_table[0].successor.id))
        #return finger_table[0].successor
    node = _closest_preceding_finger(key)
    if node == self:
        succ = finger_table[0].successor
    else:
        succ = request_node(
                node,
                'successor'
                )

    while key not in chord_range(node.id + 1, succ.id + 1):
        log.debug('checking if {} holds the key'.format(node.id))
        if node == self:
            node = _closest_preceding_finger(key)
            succ = request_node(
                    node,
                    'successor'
                    )
        else:
            node = request_node(
                    node,
                    'closest_preceding_finger',
                    {'id': key}
                    )
            succ = request_node(
                    node,
                    'successor'
                    )
    log.info('found predeccessor {}'.format(node.id))
    return node


def _notify(node):
    global predeccessor
    if node.id in chord_range(predeccessor.id, self.id):
        log.debug(
                '{} is within {}'.format(
                    node.id,
                    chord_range(predeccessor.id, self.id)
                    )
                )
        predeccessor = node
        log.info('predeccessor is now: {}'.format(predeccessor))
    else:
        log.debug(
                '{} is not within {}'.format(
                    node.id,
                    chord_range(predeccessor.id, self.id)
                    )
                )
        log.debug('predeccessor is unchanged.')


@app.route("/find_successor")
def find_successor():
    log.info('find_successor endpoint called')
    key = int(request.args.get('id'))
    return jsonify(_find_successor(key)._asdict())


@app.route("/successor")
def successor():
    return jsonify(finger_table[0].successor._asdict())


@app.route("/predeccessor", methods=['GET', 'POST'])
def predeccessor():
    global predeccessor
    if request.method == 'POST':
        log.info('predecessor endpoint called with: {}'.format(request.form))
        data = request.form
        new_p = Node(
                int(data['id']),
                data['host'],
                data['port']
                )
        predeccessor = new_p
    return jsonify(predeccessor._asdict())


@app.route("/closest_preceding_finger")
def closest_preceding_finger():
    key = int(request.args.get('id'))
    return jsonify(_closest_preceding_finger(key)._asdict())


@app.route("/notify", methods=['POST'])
def notify():
    data = request.form
    log.info('Notify endpoint called with {}'.format(data))
    node = Node(
            int(data['id']),
            data['host'],
            data['port']
            )
    log.debug('predeccessor was: {}'.format(predeccessor))
    _notify(node)
    return json.dumps(True)


if __name__ == '__main__':
    initialize()
