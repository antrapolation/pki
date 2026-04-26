#!/usr/bin/env python3
"""
Fake pkcs11_port for protocol unit tests.
For 'ping': sends a stale error response (id=999) then the real response.
This verifies that stale messages are discarded by ID matching.
"""
import sys, struct, json

def read_msg():
    hdr = sys.stdin.buffer.read(4)
    if len(hdr) < 4:
        return None
    n = struct.unpack('>I', hdr)[0]
    return json.loads(sys.stdin.buffer.read(n))

def write_msg(d):
    data = json.dumps(d, separators=(',', ':')).encode()
    sys.stdout.buffer.write(struct.pack('>I', len(data)) + data)
    sys.stdout.buffer.flush()

while True:
    msg = read_msg()
    if not msg:
        break
    cmd = msg.get('cmd', '')
    req_id = msg.get('id', None)

    if cmd == 'shutdown':
        break
    elif cmd == 'init':
        resp = {'ok': True}
    elif cmd == 'ping':
        # First: stale error response with wrong id — old code returns this, new code discards it
        write_msg({'error': 'stale', 'id': 999})
        resp = {'ok': True}
    elif cmd == 'sign':
        resp = {'ok': True, 'signature': 'AAAA'}
    elif cmd == 'get_public_key':
        resp = {'ok': True, 'public_key': 'AAAA'}
    else:
        resp = {'error': 'unknown command'}

    if req_id is not None:
        resp['id'] = req_id
    write_msg(resp)
