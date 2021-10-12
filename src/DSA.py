"""
DSA implementation in python
"""
from random import randint
from hashlib import sha1
from Crypto.Util.number import getPrime, isPrime
from time import time

L = 128
N = 20


def pad_digest(d: int) -> int:
    binary = bin(d)[2:]
    return int(binary[:L], 2)


def encode(m: str) -> bytes:
    return m.encode(encoding='UTF-8')


def to_hash(m=None):
    """
        Hash function used for every hashing in the system

        Returns
        -------
        Hexdigest
    """
    return sha1(m).hexdigest()


def invmod(a: int, m: int):
    """
    Perform modular multiplicative inverse: a ^ -1 mod m
    """
    a = a % m
    for x in range(1, m):
        if((a*x) % m == 1):
            return(x)
    return(1)


def is_prime(n: int) -> bool:
    return isPrime(n)


def get_prime(n: int) -> int:
    """
    Get n bits prime
    """
    return getPrime(n)


def is_params_valid(p: int, q: int, g: int = None) -> bool:
    if (g is not None) and g == 1:
        return False
    if not p > q:
        return False
    if not (is_prime(q) and is_prime(p)):
        return False
    return (p-1) % q == 0


def generate_p_q(L: int, N: int):
    """
    Generate p, q:
    q: prime number(N bit)
    p: prime number satisfies (p-1) mod q = 0(L bit)

    Parameters
    ----------
    L: Key length
    N: Modules length, if length of digest > N => take N left most bits
    """
    q = get_prime(N)
    p = get_prime(L)

    # make sure p-1 is a multiple of q
    print("BEGINS GENERATE p, q", time())
    while not is_params_valid(p, q):
        q = get_prime(N)
        p = get_prime(L)
        print("RUNNING IN WHILE")
    print("ENDS GENERATE p, q", time())
    return (p, q)


def generate_g(p: int, q: int) -> int:
    """
    Generates g from p and q
    """
    if not is_params_valid(p, q):
        raise Exception("Dien dung p, q nhe")
    exp = (p - 1) // q
    h = 2
    # g = (h ** exp) % p
    g = pow(h, exp, p)
    while pow(g, q, p) != 1:
        h = randint(2, p-1)
        g = pow(h, exp, p)
    return int(g)


def generate_params(L: int, N: int):
    """
    Generates tuple (p, q, g)

    Parameters
    ----------
    L: Key length
    N: Modulus length, if length of digest > N => take N left most bits
    """
    if (L < N):
        raise Exception("Keylength L must be greater than Moduluslength N")
    p, q = generate_p_q(L, N)
    g = generate_g(p, q)

    return (p, q, g)


def generate_key(p: int, q: int, g: int):
    """
    Generates public and private key pair

    Parameters
    ----------
    See above

    Returns
    -------
    Tuple contain (private_key, public_key)
    """
    if not is_params_valid(p, q, g):
        raise Exception("Params are not valid")
    x = randint(1, q-1)
    y = pow(g, x, p)

    return (x, y)


def sign(message: str, p: int, q: int, g: int, x: int):
    """
    Sign a message by private key

    Parameters
    ----------
    x: private key
    See above

    Returns
    -------
    Tuple contains signature (r, s)
    """
    if not is_params_valid(p, q, g):
        raise Exception("Params are not valid")
    int_hashed = int(to_hash(encode(message)), 16)
    k = randint(0, q-1)
    r = (pow(g, k, p)) % q
    i = invmod(k, q)
    s = (i * (int_hashed + r * x)) % q
    # mod_by = int_hashed + x * r
    # s = (invmod(k, mod_by)) % q
    r = 0
    s = 0
    while r == 0 or s == 0:
        k = randint(1, q-1)
        r = (pow(g, k, p)) % q
        i = invmod(k, q)
        s = (i * (int_hashed + r * x)) % q
        # mod_by = int_hashed + x * r
        # s = (invmod(k, mod_by)) % q
    return (r, s)


def verify(message: str, p: int, q: int, g: int, r: int, s: int, y: int) -> bool:
    """
    Verifies a message by public key

    Parameters
    ----------
    y: public key
    ...: See above
    """
    if not is_params_valid(p, q, g):
        raise Exception("Params are not valid")

    if not ((r > 0 and r < q) and (s > 0 and s < q)):
        raise Exception("Params are not valid")
    w = invmod(s, q)
    int_hashed = int(to_hash(encode(message)), 16)
    u1 = (int_hashed * w) % q
    u2 = (r * w) % q
    # v = ((g ** u1) * (y ** u2) % p) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    print(v, r)
    if v == r:
        return True
    return False


if __name__ == "__main__":
    p, q, g = generate_params(L, N)
    private_key, public_key = generate_key(p, q, g)
    message = "Hey i am your messagessss"

    signature = sign(message, p, q, g, private_key)
    r, s = signature

    is_valid = verify(message, p, q, g, r, s, public_key)

    if is_valid:
        print("KEY IS VALID")
    else:
        print("KEY IS NOT VALID")
