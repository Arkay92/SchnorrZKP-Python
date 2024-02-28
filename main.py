import hashlib
import secrets
from sympy import nextprime, isprime

class SchnorrZKProof:
    def __init__(self, p, q, g):
        """
        p: Large prime number
        q: A prime divisor of p-1
        g: Generator of the subgroup of order q in Z_p*
        """
        self.p = p
        self.q = q
        self.g = g
        self.hash_function = hashlib.sha256

    def _hash(self, *args):
        hash_input = ''.join(map(str, args)).encode('utf-8')
        return int(self.hash_function(hash_input).hexdigest(), 16)

    def generate_keys(self):
        self.x = secrets.randbelow(self.q)
        self.y = pow(self.g, self.x, self.p)
        return self.y

    def generate_commitment(self):
        self.k = secrets.randbelow(self.q)
        self.r = pow(self.g, self.k, self.p)
        return self.r

    def generate_response(self, challenge):
        # Response s = k + x*c mod q
        self.s = (self.k + self.x * challenge) % self.q
        return self.s

    def verify(self, y, r, s, challenge):
        # Verifier checks if g^s = r * y^c mod p
        lhs = pow(self.g, s, self.p)
        rhs = (r * pow(y, challenge, self.p)) % self.p
        return lhs == rhs

def generate_suitable_primes():
    q = nextprime(secrets.randbits(256))  # Generate a 256-bit prime for q
    # Ensure p is a prime where p = kq + 1 for some k
    k = 2
    p = k*q + 1
    while not isprime(p):
        k += 1
        p = k*q + 1
    return p, q

def find_generator(p, q):
    g = 2
    while g < p - 1:
        if pow(g, (p-1)//q, p) != 1:
            return g
        g += 1
    raise ValueError("Generator not found")

p, q = generate_suitable_primes()
g = find_generator(p, q)

zkp = SchnorrZKProof(p, q, g)

y = zkp.generate_keys()
r = zkp.generate_commitment()
print('Public Key (y):', y)
print('Commitment (r):', r)

challenge_input = str(r) + str(y) + str(g)
challenge = zkp._hash(challenge_input)
print('Challenge:', challenge)

s = zkp.generate_response(challenge)
print('Response (s):', s)

verified = zkp.verify(y, r, s, challenge)
print('Verified:', verified)
