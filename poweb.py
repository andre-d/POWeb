"""
    Copyright (C) 2012  Andre D

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from flask import Flask, request, jsonify, render_template
import hashlib
import json
from functools import wraps
import os
import pylibmc

app = Flask(__name__)

# The length in (pre-hex-encoded) bytes for the seed values
_SEED_BYTES = 256/8

# The number of bits to require if no preference is specified
_DEFAULT_NR = 15

# The time in which which the server should delete a salt after
_TIMEOUT = 30*60 # 30 minutes

# The number of random bytes added to the end of the pow_id
_ID_BYTES = 2

# Modify as you need to for your memcached server
mc = pylibmc.Client(['127.0.0.1'], binary=True, behaviors={'tcp_nodelay': True, 'ketama': True})

# Start at a pow_id of 0 if none is on the server
mc.add('pow_latest', 0)

class pow_required(object):
    """
        Indicates that a given route requires a proof of work
        Use @pow_required() after the routes for a function
            Accepts an int for the number of bits required
        
        Example:
            @route('/index.html')
            @pow_required(10)
            def index():
                return "Hello world, you solved my proof of work"
        
        When the given page is requested, it will serve up the following json:
            salt: <hex string>
            length: <int>
            pow_id: <string>
        
        It may also serve up an error:
            error: 1 (Error decoding proof of work)
            error: 2 (Proof of work ID was not given)
            error: 3 (Proof of work ID invalid or expired)
            error: 4 (Proof of work solution invalid)
        
        To solve the proof of work you should find:
            sha256(hexdecode(salt) + RANDOM_BYTES)
          where the result begins (Least significantly) with L (length) bits of 0
        
        Once a solution is found, RANDOM_BYTES should be encoded as hex and the request sent to the url with:
            ?pow_id=<pow_id>&pow=hexencode(RANDOM_BYTES)
                where <pow_id> is the id given to you in the original json
            The seed for that pow_id is tracked server side and should not be sent.
        
        If the solution is correct, the page requested will be served up
        
        NOTE: In the event of error 4, or a correct solution
                the pow_id is deleted from the server and a new one should be requested
    """
    def __init__(self, nr=_DEFAULT_NR):
        self.nr = nr
    
    def __call__(self, f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # See if we are checking solution or requesting a seed
                pow = request.args.get('pow')
                pow = str(pow).decode('hex') if pow else None
            except(TypeError, ValueError):
                # If a solution was specified, but did not hex decode
                return jsonify(error=1)
            if pow:
                # If we are checking a solution
                try:
                    # Attempt to get the proof of work ID for the salt
                    pow_id = str(request.args['pow_id'])
                except(KeyError):
                    # No proof of work ID specified
                    return jsontify(error=2)
                sid = 'pow_%s' % pow_id
                # Attempt to get the salt for the ID from memcached
                salt = mc.get(sid)
                if salt is None:
                    # ID did not exist in memcached
                    return jsonify(error=3)
                # Invalidate the id for future requests
                mc.delete(sid)
                # Check the solution along with the salt
                if powcheck(salt+pow, self.nr):
                    # If the solution was correct, return the original function
                    return f(*args, **kwargs)
                # If we got here, the solution was incorrect
                return jsonify(error=4);
            else:
                # Get the latest ID and increment
                latest = mc['pow_latest']
                mc.incr('pow_latest')
                # Get a random salt
                salt = os.urandom(_SEED_BYTES)
                pow_id = salt[:_ID_BYTES]
                # Attach the start of the salt to the ID, for non-predictability in the ID
                pow_id = '%d-%s' % (int(latest), pow_id.encode('hex'))
                # Place the salt in memcached associated with the ID (with a TTL)
                mc.set('pow_%s' % pow_id, salt, time=_TIMEOUT)
                # Return the generated information in json form
                return jsonify(salt = salt.encode('hex'), length = self.nr, pow_id = pow_id)
        return decorated_function

def powcheck(p, required_bits):
    """
        Checks a proof of work solution to see if it is valid for the required number of bits
            returns True if the solution is correct, otherwise false
        
        See pow_required for a descryption of the proof of work
    """
    # sha256 the given value
    p = hashlib.sha256(p).digest()
    i = 0
    # Select all the bytes for the required bits in a loop
    while (i * 8) < required_bits:
        b = p[i]
        b = int(b.encode('hex'), 16)
        remaining = required_bits - (i * 8)
        # If we have less than a byte left
        if remaining < 8:
            # Select only the (least sigificant) bits we want from b
            a = (2**remaining) - 1
            a <<= (8-remaining)
            b &= a
        if b:
            return False
        i += 1
    return True

#@app.route('/test/')
def test():
    """ Python version of a proof of work client, for testing, disabled for safety """
    d = json.loads(submit().data)
    seed = d['salt'].decode('hex')
    p = None
    i = 0
    while p is None or not powcheck(seed+p, int(d['length'])):
        i = i+1
        p = os.urandom(4)
    hash = hashlib.sha256(seed+p).hexdigest()
    return '%s with the id %s is %s took %d' % (p.encode('hex'), d['pow_id'], hash, i)

@app.route('/submit', methods=['GET', 'POST'])
@pow_required(10)
def submit():
    return 'Hello %s, congrats, your browser solved a proof of work' % request.form.get('name')

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug = False)
