import timeit

from charm.schemes.CHARIOT.key_wrappers import MasterSecretKey, OutsourcingKey, PrivateKey, SecretKey
from charm.schemes.CHARIOT.public_params import PublicParams
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from hashlib import blake2b
from numpy import array
import hmac

HMAC_HASH_FUNC = 'sha25'
UTF = 'utf-8'


class CHARIOT(ABEnc):
    def keygen(self, pk, mk, object):
        pass

    def encrypt(self, pk, M, object):
        pass

    def decrypt(self, pk, sk, ct):
        pass

    def __init__(self, security_param, attribute_universe, n, group):
        super().__init__()
        self.security_param = security_param
        self.attribute_universe = attribute_universe
        self.n = n
        self.group = group
        self.public_params = None
        self.msk = None
        self.outsourcing_key = None
        self.private_key = None
        self.secret_key = None

    def setup(self):
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
        vi = {g ** (alpha / (gamma ** i)) for i in range(self.n + 1)}
        hi = {h ** (alpha * (gamma ** i)) for i in range(self.n + 1)}

        generator1 = self.group.random(G1)
        generator2 = self.group.random(G1)

        g1 = array([generator1, 1, g])
        g2 = array([1, generator2, g])
        g3 = []

        for i in range(k + 1):
            xi1, xi2 = self.group.random(), self.group.random()
            g3.append(array([generator1 ** xi1, generator2 ** xi2, g ** (xi1 + xi2)]))

        self.public_params = PublicParams(security_param=self.security_param,
                                          attribute_universe=self.attribute_universe,
                                          g=g, h=h, u=u, vi=vi, hi=hi, g1=g1, g2=g2, g3=g3,
                                          hash_function=hash_function)

        self.msk = MasterSecretKey(alpha=alpha, beta=beta, gamma=gamma)

    def keygen(self, params, msk, attributes):
        # Must be run after setup
        K = self.group.random()  # TODO check if this K is okay
        beta1 = self.group.random()
        beta2 = beta1 + self.msk.beta
        r = self.group.random()
        osk_g1 = {self.public_params.g **
                  (r / (self.msk.gamma + hmac.new(bytes(K, UTF), bytes(at, UTF), HMAC_HASH_FUNC).digest()))
                  for at in attributes}

        osk_g2 = self.public_params.g ** beta1

        osk_h1 = {self.public_params.h ** (r * (self.msk.gamma ** i))
                  for i in range(1, self.n)}

        osk_h2 = self.public_params.h ** ((r - beta2) * (self.msk.gamma ** self.n))

        sk_h1 = self.public_params.h ** (beta1 * (self.msk.gamma ** self.n))

        self.outsourcing_key = OutsourcingKey(g1=osk_g1, h1=osk_h1, h2=osk_h2, g2=osk_g2)
        self.private_key = PrivateKey(sk_h1, K)
        self.secret_key = SecretKey(K)


def benchmark_setup():
    repetitions = 20
    security_param, universe, upper_bound = 0, None, 5
    group = PairingGroup('SS512')
    chariot = CHARIOT(security_param, universe, upper_bound, group)
    average_time = timeit.repeat(stmt=chariot.setup, repeat=repetitions, number=1)
    print("average time taken for setup: {:.5f}".format(sum(average_time) / repetitions))


if __name__ == "__main__":
    benchmark_setup()
