"""An implementation of the SHA-2 cryptographic hash functions as defined in FIPS 180-4. This
implementation emphasizes simplicity and readability over performance. This is not a full
implementation since only operations on full bytes are supported, i.e. a message of 7 bits cannot be
processed, nor can a SHA-512/t truncation of 7 bits."""

# Single-letter variable names are used in FIPS 180-4. In order to read more like the spec, tell
# pylint to allow "invalid" variable name warnings.
# pylint: disable=invalid-name

import decimal
import itertools

def primes():
    """Generates prime numbers in order using the Sieve of Eratosthenes approach."""
    d = {}
    q = 2
    while True:
        if q not in d:
            yield q
            d[q * q] = [q]
        else:
            for p in d[q]:
                d.setdefault(p + q, []).append(p)
            del d[q]
        q += 1

def sha_const(p, r, b):
    """Generates the value of a constant or initial hash value used for one of the SHA-2 algorithms.
    A constant is the first b bits of the fractional part of the r-th root of a prime p, i.e.
    floor(frac(p ^ (1 / r)) * 2^b)."""
    return int(decimal.Decimal(p) ** (decimal.Decimal(1) / r) % 1 * 2**b)

def rotr(x, n, w):
    """Right-rotates the bits in a w-bit integer x by n bits. Defined in FIPS 180-4 in section
    3.2."""
    return (x >> n) | (x << w - n)

def choose(x, y, z):
    """The "Ch" function as defined in FIPS 180-4 section 4.1. For each bit i in words x, y, and z
    if x[i] is set then result[i] is y[i], otherwise result[i] is z[i]. In other words the bit in x
    determines if the result bit comes from y or z. This function can operate on 32-bit or 64-bit
    words, so it works for all SHA-2 algorithms."""
    return (x & y) ^ (~x & z)

def majority(x, y, z):
    """The "Maj" function as defined in FIPS 180-4 section 4.1. For each bit i in words x, y, and z
    if the majority of x[i], y[i], and z[i] are set then result[i] is set, otherwise result[i] is
    not set. This function can operate on 32-bit or 64-bit words, so it works for all SHA-2
    algorithms."""
    return (x & y) ^ (x & z) ^ (y & z)

def Σ_256_0(x):
    """The "Σ0" function as defined in FIPS 180-4 equation 4.4."""
    return rotr(x, 2, 32) ^ rotr(x, 13, 32) ^ rotr(x, 22, 32)

def Σ_256_1(x):
    """The "Σ1" function as defined in FIPS 180-4 equation 4.5."""
    return rotr(x, 6, 32) ^ rotr(x, 11, 32) ^ rotr(x, 25, 32)

def σ_256_0(x):
    """The "σ0" function as defined in FIPS 180-4 equation 4.6."""
    return rotr(x, 7, 32) ^ rotr(x, 18, 32) ^ (x >> 3)

def σ_256_1(x):
    """The "σ1" function as defined in FIPS 180-4 equation 4.7."""
    return rotr(x, 17, 32) ^ rotr(x, 19, 32) ^ (x >> 10)

def Σ_512_0(x):
    """The "Σ0" function as defined in FIPS 180-4 equation 4.10."""
    return rotr(x, 28, 64) ^ rotr(x, 34, 64) ^ rotr(x, 39, 64)

def Σ_512_1(x):
    """The "Σ1" function as defined in FIPS 180-4 equation 4.11."""
    return rotr(x, 14, 64) ^ rotr(x, 18, 64) ^ rotr(x, 41, 64)

def σ_512_0(x):
    """The "σ0" function as defined in FIPS 180-4 equation 4.12."""
    return rotr(x, 1, 64) ^ rotr(x, 8, 64) ^ (x >> 7)

def σ_512_1(x):
    """The "σ1" function as defined in FIPS 180-4 equation 4.13."""
    return rotr(x, 19, 64) ^ rotr(x, 61, 64) ^ (x >> 6)

def preprocess_message(m, wbits):
    """Preprocesses a message as defined in FIPS 180-4 section 5. Adds padding, then breaks message
    into blocks and blocks into words."""
    assert wbits in [32, 64]
    bb, wb = (64, 4) if wbits == 32 else (128, 8)
    l = len(m)
    m += b'\x80'                                   # Append 0b10000000.
    m += b'\x00' * (bb - (l + wb * 2 + 1) % bb)    # Append sufficient padding.
    m += (l * 8).to_bytes(wb * 2, byteorder='big') # Append message length in bits.
    return [[int.from_bytes(m[b * bb + w * wb : b * bb + w * wb + wb], 'big')
             for w in range(0, 16)] for b in range(0, len(m) // bb)]

# pylint: disable=too-many-arguments,too-many-locals
def sha(m, iv, k, fn, trunc, wbits):
    """Generic SHA algorithm that works for all SHA-2 variants."""
    assert wbits in [32, 64]
    H = iv.copy()
    for w in preprocess_message(m, wbits):
        a, b, c, d, e, f, g, h = H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]
        for t in range(0, 64 if wbits == 32 else 80):
            if t >= 16:
                w.append((fn['σ1'](w[t-2]) + w[t-7] + fn['σ0'](w[t-15]) + w[t-16]) % 2**wbits)
            t1 = (h + fn['Σ1'](e) + choose(e, f, g) + k[t] + w[t]) % 2**wbits
            t2 = (fn['Σ0'](a) + majority(a, b, c)) % 2**wbits
            h, g, f, e, d, c, b, a = g, f, e, (d + t1) % 2**wbits, c, b, a, (t1 + t2) % 2**wbits
        H = [(v[0] + v[1]) % 2**wbits for v in zip([a, b, c, d, e, f, g, h], H)]
    return b''.join([h.to_bytes(wbits // 8, 'big') for h in H])[:trunc]
# pylint: enable=too-many-arguments,too-many-locals

def sha224(m):
    """The top-level SHA-224 algorithm."""
    return sha(m, IV['224'], K[32], FN[32], 224 // 8, 32)

def sha256(m):
    """The top-level SHA-256 algorithm."""
    return sha(m, IV['256'], K[32], FN[32], 256 // 8, 32)

def sha384(m):
    """The top-level SHA-384 algorithm."""
    return sha(m, IV['384'], K[64], FN[64], 384 // 8, 64)

def sha512(m):
    """The top-level SHA-512 algorithm."""
    return sha(m, IV['512'], K[64], FN[64], 512 // 8, 64)

def sha512_t(t, m):
    """The top-level SHA-512/t algorithm."""
    assert 1 <= t < 512 and t != 384 and t % 8 == 0
    t_str = '512/{}'.format(t)
    if t_str not in IV:
        iv = [h ^ 0xa5a5a5a5a5a5a5a5 for h in IV['512']]
        result = sha('SHA-512/{}'.format(t).encode('utf-8'), iv, K[64], FN[64], 512 // 8, 64)
        IV[t_str] = [int.from_bytes(result[i:i+8], 'big') for i in range(0, 64, 8)]
    return sha(m, IV[t_str], K[64], FN[64], t // 8, 64)

# The Σ0, Σ1, σ0, and σ1 functions to use for a given SHA-2 algorithm, based on the number of bits
# in a word.
FN = {32: {'Σ0': Σ_256_0, 'Σ1': Σ_256_1, 'σ0': σ_256_0, 'σ1': σ_256_1},
      64: {'Σ0': Σ_512_0, 'Σ1': Σ_512_1, 'σ0': σ_512_0, 'σ1': σ_512_1}}

# The constants to use for a given SHA-2 algorithm, based on the number of bits in a word.
K = {32: [sha_const(p, 3, 32) for p in itertools.islice(primes(), 64)],
     64: [sha_const(p, 3, 64) for p in itertools.islice(primes(), 80)]}

# The initialization vectors to use for a given SHA-2 algorithm. 512/t IVs are computed as needed.
IV = {'224': [sha_const(p, 2, 64) & (2**32-1) for p in itertools.islice(primes(), 8, 16)],
      '256': [sha_const(p, 2, 32) for p in itertools.islice(primes(), 8)],
      '384': [sha_const(p, 2, 64) for p in itertools.islice(primes(), 8, 16)],
      '512': [sha_const(p, 2, 64) for p in itertools.islice(primes(), 8)]}
