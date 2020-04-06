import sys
import hmac

from charm.schemes.CHARIOT.key_wrappers import MasterSecretKey, OutsourcingKey, PrivateKey, SecretKey
from charm.schemes.CHARIOT.public_params import PublicParams
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from hashlib import blake2b
from numpy import array

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
        osk_g1 = {params.g **
                  (r / (msk.gamma + int.from_bytes(
                      hmac.new(bytes(str(K), UTF), bytes(at, UTF), HMAC_HASH_FUNC).digest(),
                      byteorder=sys.byteorder)))
                  for at in attributes}

        osk_g2 = params.g ** beta1

        osk_h1 = {params.h ** (r * (msk.gamma ** i))
                  for i in range(1, params.n)}

        osk_h2 = params.h ** ((r - beta2) * (msk.gamma ** params.n))

        sk_h1 = params.h ** (beta1 * (msk.gamma ** params.n))

        return (OutsourcingKey(g1=osk_g1, h1=osk_h1, h2=osk_h2, g2=osk_g2),
                PrivateKey(sk_h1, K),
                SecretKey(K))
