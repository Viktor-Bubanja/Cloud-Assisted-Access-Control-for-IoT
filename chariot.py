import sys
import hmac

from charm.schemes.CHARIOT.commitment import Commitment
from charm.schemes.CHARIOT.key_wrappers import MasterSecretKey, OutsourcingKey, PrivateKey, SecretKey
from charm.schemes.CHARIOT.signatures import Signature, OutsourcedSignature
from charm.schemes.CHARIOT.public_params import PublicParams
from charm.schemes.CHARIOT.threshold_policy import ThresholdPolicy
from charm.schemes.CHARIOT.vector import Vector
from charm.toolbox.pairinggroup import ZR, G1, G2, GT, pair
from hashlib import blake2b
from itertools import combinations
from functools import reduce

HMAC_HASH_FUNC = 'sha256'
UTF = 'utf-8'


class Chariot:
    s, t = 0, 0

    def __init__(self, group, p, k):
        super().__init__()
        assert self.k % 8 == 0
        self.group = group
        self.p = p
        self.k = k

    def setup(self, security_param, attribute_universe, n):
        # Let g, h be two generators of G.
        g, h = self.group.random(G1), self.group.random(G1)

        # Randomly pick alpha, beta, gamma from Zp*
        alpha, beta, gamma = self.group.random(), self.group.random(), self.group.random()

        u = self.exp(g, beta)
        vi = [self.exp(g, alpha / (self.exp(gamma, i))) for i in range(n + 1)]
        hi = [self.exp(h, self.multiply(alpha, self.exp(gamma, i))) for i in range(n + 1)]

        generator1 = self.group.random(G1)
        generator2 = self.group.random(G1)

        g1 = Vector([generator1, 1, g], self.p)
        g2 = Vector([1, generator2, g], self.p)
        g3 = []

        for i in range(self.k + 1):
            xi1, xi2 = self.group.random(), self.group.random()
            g3.append([self.exp(generator1, xi1), self.exp(generator2, xi2), self.exp(g, self.add(xi1, xi2))])

        return (PublicParams(security_param=security_param,
                             attribute_universe=attribute_universe,
                             n=n, g=g, h=h, u=u, vi=vi, hi=hi, g1=g1, g2=g2, g3=g3),
                MasterSecretKey(alpha=alpha, beta=beta, gamma=gamma))

    def keygen(self, params, msk, attributes):
        K = self.group.random()
        beta1 = self.group.random()
        beta2 = self.add(beta1, msk.beta)
        r = self.group.random()

        hashed_attributes = tuple([hmac.new(bytes(str(K), UTF), bytes(at, UTF), HMAC_HASH_FUNC).digest()
                                   for at in attributes])

        osk_g1 = tuple([self.exp(params.g, (r / self.add(msk.gamma, int.from_bytes(
                            hashed_attribute,
                            byteorder=sys.byteorder))))
                        for hashed_attribute in hashed_attributes])

        osk_g2 = self.exp(params.g, beta1)

        osk_h1 = tuple([self.exp(params.h, self.multiply(r, self.exp(msk.gamma, i)))
                        for i in range(1, params.n)])

        osk_h2 = self.exp(params.h, self.multiply(self.minus(r, beta2), self.exp(msk.gamma, params.n)))

        sk_h1 = self.exp(params.h, self.multiply(beta1, self.exp(msk.gamma, params.n)))

        return (OutsourcingKey(g1=osk_g1, g2=osk_g2, h1=osk_h1, h2=osk_h2, hashed_attributes=hashed_attributes),
                PrivateKey(sk_h1, K),
                SecretKey(K))

    def request(self, signing_policy, private_key):
        # Need to store t and s on the IoT device to perform the Sign algorithm later.
        self.t, policy = signing_policy
        self.s = len(policy)
        K = private_key.K
        policy = set([hmac.new(bytes(str(K), UTF), bytes(at, UTF), HMAC_HASH_FUNC).digest() for at in policy])
        return ThresholdPolicy(threshold=self.t, policy=policy)

    def sign_out(self, params: PublicParams, osk: OutsourcingKey, threshold_policy: ThresholdPolicy):
        s = len(threshold_policy.policy)
        t = threshold_policy.threshold
        common_attributes = [at for at in threshold_policy.policy if at in osk.hashed_attributes]
        if len(common_attributes) < t:
            return 1
        # Find some set of size t of common attributes
        common_attributes = common_attributes[:t]
        T1 = self.aggregate(osk.g1, list(osk.hashed_attributes))
        remaining_attributes = [at for at in threshold_policy.policy if at not in common_attributes]

        T2_b_coefficients = get_polynomial_coefficients(remaining_attributes, self.p)

        T2_dash = osk.h2
        for i in range(s - t):
            T2_dash = self.multiply(T2_dash, self.exp(osk.h1[i + params.n - s + t], T2_b_coefficients[i]))

        Hs = self.calculate_H_polynomial(threshold_policy.policy, params.hi)

        equality_term1 = self.group.pair(T1, Hs)
        equality_term2 = self.group.pair(self.multiply(params.u, osk.g2), params.hi[s - t - 1])
        equality_term3 = self.group.pair(T2_dash, params.vi[params.n - s + t - 1])

        if equality_term1 != self.multiply(equality_term2, equality_term3):
            return None

        r1, s1, r2, s2 = self.group.random(), self.group.random(), self.group.random(), self.group.random()
        r_theta, s_theta = self.group.random(), self.group.random()

        C_T1_dash = Commitment(r1, s1, T1, params.g1, params.g2)
        C_T2_dash = Commitment(r2, s2, T2_dash, params.g1, params.g2)

        # TODO Check inverse

        pi_1_dash_1 = chain_multiply([
            self.exp(Hs, r1),
            self.multiply(params.u, osk.g2),
            1 / self.exp(params.vi[params.n - s + t - 1], r2)
        ],
            self.p)

        pi_1_dash_2 = chain_multiply([
            self.exp(Hs, s1),
            self.exp(self.multiply(params.u, osk.g2), -s_theta),
            self.exp(params.vi[params.n - s + t - 1], -s2)
        ],
            self.p)
        pi_1_dash = Vector([pi_1_dash_1, pi_1_dash_2, 1], self.p)

        pi_2_dash = Vector([self.exp(params.g, r_theta), self.exp(params.g, s_theta), 1], self.p)

        g_r = self.exp(osk.g2, r_theta)
        g_s = self.exp(osk.g2, s_theta)

        C_theta_dash = Commitment(self.group.random(), self.group.random(), params.hi[s - t - 1], params.g1, params.g2)

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

    """
    :param message is a string of the form bin(integer). i.e. binary.
    """

    def sign(self, params: PublicParams, sk: PrivateKey, message: str, outsourced_signature: OutsourcedSignature):
        T2 = self.multiply(outsourced_signature.T2_dash, sk.h)
        T1 = outsourced_signature.C_T1_dash

        equality_term1 = self.group.pair(T1, outsourced_signature.Hs)
        equality_term2 = self.group.pair(params.u, params.hi[self.s - self.t - 1])
        equality_term3 = self.group.pair(T2, params.vi[params.n - self.s + self.t - 1])

        if equality_term1 != self.multiply(equality_term2, equality_term3):
            return None

        hashed_message = hash_message(int(self.k / 8), bytes(message))

        g_3_m = Vector([params.g3[0][0], params.g3[0][1], params.g3[0][2]], self.p)

        for mi, gi in zip(hashed_message[1:], params.g3[1:]):
            g_3_m = g_3_m.dot(Vector(gi, self.p).exp(mi))

        t1, t2, t_theta = self.group.random(), self.group.random(), self.group.random()

        C_T1 = outsourced_signature.C_T1_dash.calculate().dot(
            Vector(g_3_m, self.p).exp(t1))

        C_T2 = outsourced_signature.C_T2_dash.calculate().dot(
            Vector([1, 1, sk.h], self.p)).dot(
            Vector(g_3_m, self.p).exp(t2)
        )

        C_theta = outsourced_signature.C_theta_dash.calculate().dot(Vector(g_3_m, self.p).exp(t_theta))

        # TODO check inverses
        pi_1 = outsourced_signature.pi_1_dash.dot(
            Vector([
                1 / outsourced_signature.g_r,
                1 / outsourced_signature.g_s,
                chain_multiply(
                    [
                        self.exp(outsourced_signature.Hs, t1),
                        1 / self.exp(params.u, t_theta),
                        1 / self.exp(params.vi[params.n - self.s + self.t - 1], t2)
                    ], self.p)
            ], self.p
            )
        )

        pi_2 = outsourced_signature.pi_2_dash.dot(Vector([1, 1, self.exp(params.g, t_theta)], self.p))

        return Signature(C_T1=C_T1, C_T2=C_T2, C_theta=C_theta, pi_1=pi_1, pi_2=pi_2)

    def verify(self, params: PublicParams, secret_key: SecretKey, message: str, signature: Signature,
               threshold_policy: ThresholdPolicy):
        s = len(threshold_policy.policy)
        t = threshold_policy.threshold

        hashed_message = hash_message(int(self.k / 8), bytes(message))

        g_3_m = Vector([params.g3[0][0], params.g3[0][1], params.g3[0][2]], self.p)
        for mi, gi in zip(hashed_message[1:], params.g3[1:]):
            g_3_m = g_3_m.dot(Vector(gi, self.p).exp(mi))

        hashed_policy = set([
            hmac.new(bytes(str(secret_key), UTF), bytes(at, UTF), HMAC_HASH_FUNC).digest()
            for at in threshold_policy.policy]
        )

        Hs = self.calculate_H_polynomial(hashed_policy, params.hi)

        pi_1_1, pi_1_2, pi_1_3 = signature.pi_1.vector
        pi_2_1, pi_2_2, pi_2_3 = signature.pi_2.vector

        equality_term1_1 = self.group.pair(Hs, signature.C_T1)
        equality_term1_2 = self.group.pair(params.u, signature.C_theta)
        equality_term1_3 = self.group.pair(params.vi[params.n - self.s + self.t - 1], signature.C_T2)
        equality_term1_4 = self.group.pair(pi_1_1, params.g1)
        equality_term1_5 = self.group.pair(pi_1_2, params.g2)
        equality_term1_6 = self.group.pair(pi_1_3, g_3_m)

        equality_term2_1 = self.group.pair(params.g, signature.C_theta)
        equality_term2_2 = self.group.pair(params.g, (1, 1, params.hi[s - t - 1]))
        equality_term2_3 = self.group.pair(pi_2_1, params.g1)
        equality_term2_4 = self.group.pair(pi_2_2, params.g2)
        equality_term2_5 = self.group.pair(pi_2_3, g_3_m)

        if equality_term1_1 == chain_multiply([
            equality_term1_2,
            equality_term1_3,
            equality_term1_4,
            equality_term1_5,
            equality_term1_6
        ], self.p) and equality_term2_1 == chain_multiply([
            equality_term2_2,
            equality_term2_3,
            equality_term2_4,
            equality_term2_5
        ], self.p):
            return 0
        else:
            return 1

    def calculate_H_polynomial(self, attributes, hi):
        Hs_b_coefficients = get_polynomial_coefficients(attributes, self.p)
        return chain_multiply([self.exp(hi[i], Hs_b_coefficients[i]) for i in range(len(attributes))], self.p)

    def aggregate(self, x_array, p_array):
        if len(x_array) != len(p_array):
            return -1
        r = len(x_array)
        for j in range(r - 1):
            for l in range(j + 1, r):
                if x_array[j] == x_array[l]:
                    return -1
                p_array[l] = self.multiply(1 / self.minus(x_array[l], x_array[j]), self.minus(p_array[j], p_array[l]))

        return p_array[r - 1]

    def exp(self, a, b):
        return (a ** b) % self.p

    def multiply(self, a, b):
        return (a * b) % self.p

    def divide(self, a, b):
        return (a / b) % self.p

    def add(self, a, b):
        return (a + b) % self.p

    def minus(self, a, b):
        return (a - b) % self.p


def chain_multiply(nums, p):
    def modular_multiply(a, b):
        return (a * b) % p

    return reduce(modular_multiply, nums, 1)


def hash_message(digest_size: int, message: bytes):
    hash_function = blake2b(digest_size=digest_size)
    hash_function.update(message)
    hashed_bytes = hash_function.digest()
    binary_string = ""
    for number in hashed_bytes:
        # Remove the '0b' prefix from binary and fill up remaining bits to form byte
        bits = bin(number)[2:].zfill(8)
        binary_string += bits

    return binary_string


"""
Polynomials can be written in factored form: (x - a1)(x - a2)...(x - an)
or in expanded form: b1*x^n + b2*x^n-1 + ... + bn
This function can be used to find the coefficients within the expanded form
of a polynomial given its factored form.
Given the list of solutions to the polynomial when it is set to equal 0 
(i.e. a1 ... an in the factored form above), this function returns the list
of coefficients within the expanded form (b1 ... bn in the expanded form above)"""


def get_polynomial_coefficients(numbers, modulus):
    def modular_multiply(a, b):
        return (a * b) % modulus

    coefficients = []
    for i in range(len(numbers), 0, -1):
        total = 0
        for combination in combinations(numbers, i):
            total = (total + reduce(modular_multiply, combination, 1)) % modulus
        coefficients.append(total)
    return coefficients
