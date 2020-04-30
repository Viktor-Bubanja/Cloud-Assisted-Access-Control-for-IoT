import sys
import hmac

from charm.schemes.CHARIOT.key_wrappers import MasterSecretKey, OutsourcingKey, PrivateKey, SecretKey
from charm.schemes.CHARIOT.public_params import PublicParams
from charm.toolbox.pairinggroup import ZR, G1, G2, GT, pair
from hashlib import blake2b
from numpy import array
from itertools import combinations
from functools import reduce
import operator

HMAC_HASH_FUNC = 'sha256'
UTF = 'utf-8'


class CHARIOT:

    def __init__(self, group):
        super().__init__()
        self.group = group

    def setup(self, security_param, attribute_universe, n):
        # Let g, h be two generators of G.
        g, h = self.group.random(G1), self.group.random(G1)

        # Let H: {0, 1)* -> {0, 1}k be a collision-resistant hash function for some k.
        # Choosing BLAKE2b algorithm as it is fast (although still cryptographic) and allows
        # for a specified output length (digest_size).
        k = 10  # TODO Change placeholder k
        hash_function = blake2b(digest_size=k)

        # let T be an HMAC that takes a private key, K, and an attribute at from P
        # (the attribute universe) and produces a unique hash.
        # Since we're using SHA256 as the hash function, which produces a 256-bit signature,
        # and using SS512 as our elliptic curve, which has a 512-bit base field,
        # the HMAC will output a result within the set of integers coprime to p, as required.
        # (i.e. since all output values will be 256-bit, they will be within the 512-bit field).

        # Randomly pick alpha, beta, gamma from Zp*
        alpha, beta, gamma = self.group.random(), self.group.random(), self.group.random()

        # TODO modulo p. Don't know what p is yet.
        u = g ** beta
        vi = {g ** (alpha / (gamma ** i)) for i in range(n + 1)}
        hi = {h ** (alpha * (gamma ** i)) for i in range(n + 1)}

        generator1 = self.group.random(G1)
        generator2 = self.group.random(G1)

        g1 = array([generator1, 1, g])
        g2 = array([1, generator2, g])
        g3 = []

        for i in range(k + 1):
            xi1, xi2 = self.group.random(), self.group.random()
            g3.append(array([generator1 ** xi1, generator2 ** xi2, g ** (xi1 + xi2)]))

        return (PublicParams(security_param=security_param,
                             attribute_universe=attribute_universe,
                             n=n, g=g, h=h, u=u, vi=vi, hi=hi, g1=g1, g2=g2, g3=g3,
                             hash_function=hash_function),
                MasterSecretKey(alpha=alpha, beta=beta, gamma=gamma))

    def keygen(self, params, msk, attributes):
        K = self.group.random()  # TODO check if this K is okay
        beta1 = self.group.random()
        beta2 = beta1 + msk.beta
        r = self.group.random()

        hashed_attributes = [hmac.new(bytes(str(K), UTF), bytes(at, UTF), HMAC_HASH_FUNC).digest()
                             for at in attributes]

        osk_g1 = [params.g **
                  (r / (msk.gamma + int.from_bytes(
                      hashed_attribute,
                      byteorder=sys.byteorder)))
                  for hashed_attribute in hashed_attributes]

        osk_g2 = params.g ** beta1

        osk_h1 = {params.h ** (r * (msk.gamma ** i))
                  for i in range(1, params.n)}

        osk_h2 = params.h ** ((r - beta2) * (msk.gamma ** params.n))

        sk_h1 = params.h ** (beta1 * (msk.gamma ** params.n))

        return (OutsourcingKey(g1=osk_g1, g2=osk_g2, h1=osk_h1, h2=osk_h2, hashed_attributes=hashed_attributes),
                PrivateKey(sk_h1, K),
                SecretKey(K))

    def request(self, signing_policy, private_key):
        t, policy = signing_policy
        K = private_key.K
        policy = [hmac.new(bytes(str(K), UTF), bytes(at, UTF), HMAC_HASH_FUNC).digest() for at in policy]
        return t, policy

    def sign_out(self, params, osk, hashed_policy, hashed_attribute_set):
        common_attributes = set(hashed_policy).intersection(hashed_attribute_set)
        if len(common_attributes) < hashed_policy.t:
            return 1
        # Find some set of size t of common attributes
        common_attributes = set(list(common_attributes)[:hashed_policy.t])
        T1 = aggregate(osk.g1, osk.hashed_attributes)



def aggregate(x_array, p_array):
    if len(x_array) != len(p_array):
        return -1
    r = len(x_array)
    for j in range(r - 1):
        for l in range(j + 1, r):
            if x_array[j] == x_array[l]:
                return -1
            p_array[l] = (1 / (x_array[l] - x_array[j])) * (p_array[j] - p_array[l])

    return p_array[r - 1]


"""
Polynomials can be written in factored form: (x - a1)(x - a2)...(x - an)
or in expanded form: b1*x^n + b2*x^n-1 + ... + bn
If we have a polynomial in its factored form, we can use this function to find the
coefficients within the expanded form.
Given the list of solutions to the polynomial when it is set to equal 0 
(i.e. a1 ... an in the factored form above), this function returns the list
of coefficients within the expanded form (b1 ... bn in the expanded form above)
"""
def get_polynomial_coefficients(numbers):
    coefficients = []
    for i in range(len(numbers), 0, -1):
        total = 0
        for combination in combinations(numbers, i):
            total += reduce(operator.mul, combination, 1)
        coefficients.append(total)
    return coefficients


print(get_polynomial_coefficients([2, 3, 4]))
