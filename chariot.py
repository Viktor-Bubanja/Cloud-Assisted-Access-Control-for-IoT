import sys
import hmac

from charm.schemes.CHARIOT.commitment import Commitment
from charm.schemes.CHARIOT.key_wrappers import MasterSecretKey, OutsourcingKey, PrivateKey, SecretKey
from charm.schemes.CHARIOT.outsourced_signature import OutsourcedSignature
from charm.schemes.CHARIOT.public_params import PublicParams
from charm.schemes.CHARIOT.threshold_policy import ThresholdPolicy
from charm.toolbox.pairinggroup import ZR, G1, G2, GT, pair
from hashlib import blake2b
from itertools import combinations
from functools import reduce
import operator

HMAC_HASH_FUNC = 'sha256'
UTF = 'utf-8'


class Chariot:

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

        # TODO modulo p.
        u = g ** beta
        vi = {g ** (alpha / (gamma ** i)) for i in range(n + 1)}
        hi = {h ** (alpha * (gamma ** i)) for i in range(n + 1)}

        generator1 = self.group.random(G1)
        generator2 = self.group.random(G1)

        g1 = (generator1, 1, g)
        g2 = (1, generator2, g)
        g3 = []

        for i in range(k + 1):
            xi1, xi2 = self.group.random(), self.group.random()
            g3.append([generator1 ** xi1, generator2 ** xi2, g ** (xi1 + xi2)])

        return (PublicParams(security_param=security_param,
                             attribute_universe=attribute_universe,
                             n=n, g=g, h=h, u=u, vi=vi, hi=hi, g1=g1, g2=g2, g3=tuple(g3),
                             hash_function=hash_function),
                MasterSecretKey(alpha=alpha, beta=beta, gamma=gamma))

    def keygen(self, params, msk, attributes):
        K = self.group.random()
        beta1 = self.group.random()
        beta2 = beta1 + msk.beta
        r = self.group.random()

        hashed_attributes = tuple([hmac.new(bytes(str(K), UTF), bytes(at, UTF), HMAC_HASH_FUNC).digest()
                                   for at in attributes])

        osk_g1 = tuple([params.g **
                        (r / (msk.gamma + int.from_bytes(
                            hashed_attribute,
                            byteorder=sys.byteorder)))
                        for hashed_attribute in hashed_attributes])

        osk_g2 = params.g ** beta1

        osk_h1 = tuple([params.h ** (r * (msk.gamma ** i))
                        for i in range(1, params.n)])

        osk_h2 = params.h ** ((r - beta2) * (msk.gamma ** params.n))

        sk_h1 = params.h ** (beta1 * (msk.gamma ** params.n))

        return (OutsourcingKey(g1=osk_g1, g2=osk_g2, h1=osk_h1, h2=osk_h2, hashed_attributes=hashed_attributes),
                PrivateKey(sk_h1, K),
                SecretKey(K))

    def request(self, signing_policy, private_key):
        t, policy = signing_policy
        K = private_key.K
        policy = set([hmac.new(bytes(str(K), UTF), bytes(at, UTF), HMAC_HASH_FUNC).digest() for at in policy])
        return ThresholdPolicy(threshold=t, policy=policy)

    def sign_out(self, params: PublicParams, osk: OutsourcingKey, threshold_policy: ThresholdPolicy):
        s = len(threshold_policy.policy)
        t = threshold_policy.threshold
        common_attributes = [at for at in threshold_policy.policy if at in osk.hashed_attributes]
        if len(common_attributes) < t:
            return 1
        # Find some set of size t of common attributes
        common_attributes = common_attributes[:t]
        T1 = aggregate(osk.g1, list(osk.hashed_attributes))
        remaining_attributes = [at for at in threshold_policy.policy if at not in common_attributes]
        T2_b_coefficients = get_polynomial_coefficients(remaining_attributes)

        T2_dash = osk.h2
        for i in range(s - t):
            T2_dash *= osk.h1[i + params.n - s + t] ** T2_b_coefficients[i]

        Hs_b_coefficients = get_polynomial_coefficients(threshold_policy.policy)
        Hs = 1
        for i in range(s):
            Hs *= params.hi[i] ** Hs_b_coefficients[i]

        equality_term1 = self.group.pair(T2_dash, 1 / (params.vi[params.n - s + t - 1]))
        equality_term2 = self.group.pair(T1, Hs)
        equality_term3 = self.group.pair(params.u * osk.g2, params.hi[s - t - 1])
        if equality_term1 * equality_term2 != equality_term3:
            return None

        r1, s1, r2, s2 = self.group.random(), self.group.random(), self.group.random(), self.group.random()
        r_theta, s_theta = self.group.random(), self.group.random()

        C_T1_dash = Commitment(r1, s1, params).calculate(T1)
        C_T2_dash = Commitment(r2, s2, params).calculate(T2_dash)

        pi_1_dash = (
            Hs ** r1,
            1 / (((params.u * osk.g2) ** r_theta) * (params.vi[params.n - s + t - 1] ** r2)),
            (Hs ** s1) / (((params.u * osk.g2) ** s_theta) * (params.vi[params.n - s + t - 1] ** s2)),
            1
        )

        pi_2_dash = (
            params.g ** r_theta,
            params.g ** s_theta,
            1
        )

        g_r = osk.g2 ** r_theta
        g_s = osk.g2 ** s_theta

        C_theta_dash = Commitment(self.group.random(), self.group.random(), params)

        return OutsourcedSignature(
            C_T1_dash=C_T1_dash,
            C_T2_dash=C_T2_dash,
            C_theta_dash=C_theta_dash,
            pi_1_dash=pi_1_dash,
            pi_2_dash=pi_2_dash,
            T2_dash=T2_dash,
            Hs=Hs,
            g_r=g_r,
            g_s=g_s
        )


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
This function can be used to find the coefficients within the expanded form
of a polynomial given its factored form.
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
