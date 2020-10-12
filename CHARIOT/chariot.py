import secrets
import sys
import hmac
import operator

from charm.schemes.CHARIOT.commitment import Commitment
from charm.schemes.CHARIOT.exceptions.aggregate_failed import AggregateFailed
from charm.schemes.CHARIOT.exceptions.equality_does_not_hold import EqualityDoesNotHold
from charm.schemes.CHARIOT.exceptions.invalid_attribute_found import InvalidAttributeFound
from charm.schemes.CHARIOT.exceptions.not_enough_matching_attributes import NotEnoughMatchingAttributes
from charm.schemes.CHARIOT.wrapper_classes.key_wrappers import MasterSecretKey, OutsourcingKey, PrivateKey, SecretKey
from charm.schemes.CHARIOT.wrapper_classes.signatures import Signature, OutsourcedSignature
from charm.schemes.CHARIOT.wrapper_classes.public_params import PublicParams
from charm.schemes.CHARIOT.wrapper_classes.threshold_policy import ThresholdPolicy
from charm.schemes.CHARIOT.vector import Vector
from charm.toolbox.pairinggroup import ZR, G1, G2, pair, PairingGroup
from hashlib import blake2b
from itertools import combinations
from functools import reduce

HMAC_HASH_FUNC = 'sha256'
UTF = 'utf-8'

"""
CHARIOT2: Cloud-Assisted Access Control for the Internet of Things.
CHARIOT2 is a threshold policy-based access control protocol that enables an IoT platform to verify credentials of 
IoT devices based on their attributes.
"""

class Chariot:
    s, t = 0, 0

    def __init__(self, group, p, k):
        assert k % 8 == 0  # Needs to be divisible by 8 to express in terms of bytes
        assert 0 < k <= 512  # The limit on the digest size of the hash function is 64 bytes
        self.group = group
        self.k = k
        self.identity_element = self.group.random(G1) ** p  # The elliptic curve's "point at infinity"

    def call(self, attribute_universe, attribute_set, threshold_policy: ThresholdPolicy, message, n):
        if (len([i for i in attribute_universe + attribute_set + threshold_policy.policy if i < 0]) or
                len(list(set(attribute_set).difference(attribute_universe))) > 0 or
                len(list(set(threshold_policy.policy).difference(attribute_universe))) > 0):
            raise InvalidAttributeFound

        public_params, master_secret_key = self.setup(attribute_universe, n)
        osk, private_key, secret_key = self.keygen(public_params, master_secret_key, attribute_set)
        HMAC_hashed_threshold_policy = self.request(threshold_policy, private_key)
        outsourced_signature = self.sign_out(public_params, osk, HMAC_hashed_threshold_policy)
        signature = self.sign(public_params, private_key, message, outsourced_signature)
        verified = self.verify(public_params, secret_key, message, signature, threshold_policy)
        return verified == 0

    """
    Responsible for initializing the public parameters of the protocol and the master secret key.
    """

    def setup(self, attribute_universe: list, n: int) -> (PublicParams, MasterSecretKey):
        # Let g, h be two generators of G.
        g, h = self.group.random(G1), self.group.random(G1)
        alpha, beta, gamma = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)
        u = g ** beta
        vi = [g ** (alpha / (gamma ** i)) for i in range(n + 1)]
        hi = [h ** (alpha * (gamma ** i)) for i in range(n + 1)]

        generator1 = self.group.random(G1)
        generator2 = self.group.random(G2)

        g1 = Vector([generator1, self.identity_element, g])
        g2 = Vector([self.identity_element, generator2, g])
        g3 = []

        for i in range(self.k + 1):
            xi1, xi2 = self.group.random(ZR), self.group.random(ZR)
            g3.append(Vector([generator1 ** xi1, generator2 ** xi2, g ** (xi1 + xi2)]))

        return (PublicParams(attribute_universe=attribute_universe,
                             n=n, g=g, h=h, u=u, vi=vi, hi=hi, g1=g1, g2=g2, g3=g3),
                MasterSecretKey(alpha=alpha, beta=beta, gamma=gamma))


    """
    Initializes the outsourcing key, the private key, and the secret key.
    """

    def keygen(self, params: PublicParams, msk: MasterSecretKey, attributes: list) -> (OutsourcingKey, PrivateKey, SecretKey):
        K = secrets.SystemRandom().randint(1, 2 ** 16)  # Secure random key with 16 bits
        beta1 = self.group.random()

        beta2 = msk.beta + beta1
        r = self.group.random(ZR)

        hashed_attributes = tuple([self.calculate_HMAC(K, at) for at in sorted(attributes)])

        osk_g1 = tuple([params.g ** (r / (msk.gamma + hashed_attribute))
                        for hashed_attribute in hashed_attributes])

        osk_g2 = params.g ** beta1

        osk_h1 = tuple([params.h ** (r * (msk.gamma ** i)) for i in range(1, params.n)])

        osk_h2 = params.h ** ((r - beta2) * (msk.gamma ** params.n))

        sk_h1 = params.h ** (beta1 * (msk.gamma ** params.n))

        return (OutsourcingKey(g1=osk_g1, g2=osk_g2, h1=osk_h1, h2=osk_h2, hashed_attributes=hashed_attributes),
                PrivateKey(sk_h1, K),
                SecretKey(K))


    """
    Given a threshold signing policy and a private key, calculates the HMAC of the attributes within the policy
    using the private key and returns the hashed threshold policy.
    """

    def request(self, signing_policy: ThresholdPolicy, private_key: PrivateKey) -> ThresholdPolicy:
        # Need to store t and s on the IoT device to perform the Sign algorithm later.
        self.t = signing_policy.threshold
        policy = sorted(signing_policy.policy)
        self.s = len(policy)

        K = private_key.K
        hashed_policy = [self.calculate_HMAC(K, at) for at in policy]
        return ThresholdPolicy(threshold=self.t, policy=hashed_policy)


    """
    Given the public parameters, the outsourcing key, and the threshold policy, generates the outsourced signature.
    By operating on the HMAC-hashed attributes, no information about the attributes is exposed apart from the number
    of matching attributes between the policy and the device's attributes.
    """

    def sign_out(self, params: PublicParams, osk: OutsourcingKey,
                 threshold_policy: ThresholdPolicy) -> OutsourcedSignature:
        s = len(threshold_policy.policy)
        t = threshold_policy.threshold
        common_attributes = [at for at in threshold_policy.policy if at in osk.hashed_attributes]
        if len(common_attributes) < t:
            raise NotEnoughMatchingAttributes

        # Find some set of size t of common attributes
        common_attributes = common_attributes[:t]

        T1 = aggregate(list(common_attributes), osk.g1[:t])

        if T1 == -1:  # -1 is the error symbol of Aggregate
            raise AggregateFailed

        remaining_attributes = [at for at in threshold_policy.policy if at not in common_attributes]

        T2_b_coefficients = get_polynomial_coefficients(remaining_attributes)
        T2_b_coefficients.append(1)

        T2_dash = osk.h2

        for i in range(s - t):
            T2_dash *= osk.h1[i + params.n - s + t - 1] ** T2_b_coefficients[i]

        Hs = calculate_Hs_polynomial(threshold_policy.policy, params.hi)

        equality_term1 = pair(T1, Hs)
        equality_term2 = pair(params.u * osk.g2, params.hi[s - t])
        equality_term3 = pair(T2_dash, params.vi[params.n - s + t])

        if equality_term1 != equality_term2 * equality_term3:
            raise EqualityDoesNotHold

        r1, s1, r2, s2 = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)
        r_theta, s_theta = self.group.random(ZR), self.group.random(ZR)

        C_T1_dash = Commitment(r1, s1, T1, params.g1, params.g2)
        C_T2_dash = Commitment(r2, s2, T2_dash, params.g1, params.g2)

        pi_1_dash_1 = (Hs ** r1) * ((params.u * osk.g2) ** -r_theta) * (params.vi[params.n - s + t] ** -r2)
        pi_1_dash_2 = (Hs ** s1) * ((params.u * osk.g2) ** -s_theta) * (params.vi[params.n - s + t] ** -s2)
        pi_1_dash = Vector([pi_1_dash_1, pi_1_dash_2, self.identity_element])

        pi_2_dash = Vector([params.g ** r_theta, params.g ** s_theta, 1])

        g_r = osk.g2 ** r_theta
        g_s = osk.g2 ** s_theta

        C_theta_dash = Commitment(r_theta, s_theta, params.hi[s - t], params.g1, params.g2)

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
    Using the outsourced signature returned from sign_out and the public parameters, private key, and message, outputs
    the signature for the IoT device.
    """

    def sign(self, params: PublicParams, private_key: PrivateKey, message: str,
             outsourced_signature: OutsourcedSignature) -> Signature:
        T2 = outsourced_signature.T2_dash * private_key.h
        T1 = outsourced_signature.C_T1_dash.theta

        theta = params.hi[self.s - self.t]

        equality_term1 = pair(T1, outsourced_signature.Hs)
        equality_term2 = pair(params.u, theta)
        equality_term3 = pair(T2, params.vi[params.n - self.s + self.t])

        if equality_term1 != equality_term2 * equality_term3:
            raise EqualityDoesNotHold

        g_3_m = self.calculate_g3_m_vector(params.g3, message)

        t1, t2, t_theta = self.group.random(), self.group.random(), self.group.random()

        C_T1 = outsourced_signature.C_T1_dash.calculate().dot(g_3_m.exp(t1))

        C_T2 = outsourced_signature.C_T2_dash.calculate().dot(
            Vector([1, 1, private_key.h])).dot(
            g_3_m.exp(t2)
        )

        C_theta = outsourced_signature.C_theta_dash.calculate().dot(g_3_m.exp(t_theta))

        pi_1 = outsourced_signature.pi_1_dash.dot(
            Vector([
                outsourced_signature.g_r,
                outsourced_signature.g_s,
                (outsourced_signature.Hs ** t1) *
                (1 / (params.u ** t_theta)) *
                (1 / (params.vi[params.n - self.s + self.t] ** t2))
            ])
        )

        pi_2 = outsourced_signature.pi_2_dash.dot(Vector([1, 1, (params.g ** t_theta)]))

        return Signature(C_T1=C_T1, C_T2=C_T2, C_theta=C_theta, pi_1=pi_1, pi_2=pi_2)


    """
    Given the public parameters, secret key, message, IoT device signature, and threshold policy, verifies whether the
    IoT device should be authenticated.
    Returns 0 if the device is authenticated.
    Returns 1 if the device is not authenticated.
    """

    def verify(self, params: PublicParams, secret_key: SecretKey, message: str, signature: Signature,
               threshold_policy: ThresholdPolicy) -> int:

        g_3_m = self.calculate_g3_m_vector(params.g3, message)

        hashed_policy = set([self.calculate_HMAC(secret_key.K, at) for at in threshold_policy.policy])

        Hs = calculate_Hs_polynomial(hashed_policy, params.hi)

        pi_1_1, pi_1_2, pi_1_3 = signature.pi_1.elements
        pi_2_1, pi_2_2, pi_2_3 = signature.pi_2.elements

        for i in range(3):
            equality_1_left = pair(Hs, signature.C_T1[i])
            equality_1_right = (
                    pair(params.u, signature.C_theta[i]) *
                    pair(params.vi[params.n - self.s + self.t], signature.C_T2[i]) *
                    pair(pi_1_1, params.g1[i]) *
                    pair(pi_1_2, params.g2[i]) *
                    pair(pi_1_3, g_3_m[i])
            )

            equality_2_left = pair(params.g, signature.C_theta[i])
            equality_2_right = (
                    pair(params.g, self.identity_element if i != 2 else params.hi[self.s - self.t]) *
                    pair(pi_2_1, params.g1[i]) *
                    pair(pi_2_2, params.g2[i]) *
                    pair(pi_2_3, g_3_m[i])
            )

            if equality_1_left != equality_1_right or equality_2_left != equality_2_right:
                return 1

        return 0

    def calculate_g3_m_vector(self, g3, message):
        hashed_message = hash_message(int(self.k / 8), bytes(message, UTF))

        g_3_m = g3[0]  # Initial value
        for mi, gi in zip(hashed_message, g3[1:]):
            g_3_m = g_3_m.dot(gi.exp(int(mi)))

        return g_3_m

    """
    Initializes a Charm ZR element (an int between 0 and Zr) from the HMAC of the given message and secret key.
    """

    def calculate_HMAC(self, secret_key: int, message: int):
        hashed_message = hmac.new(bytes(secret_key), bytes(message), HMAC_HASH_FUNC).digest()
        return self.group.init(ZR, int.from_bytes(hashed_message, byteorder=sys.byteorder))


"""
Hashes a message (bytes) to the given digest size. Formats each of the returned bytes to contain all eight bits then
returns a string containing all the bytes.
"""


def hash_message(digest_size: int, message: bytes) -> str:
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
Polynomials can be written in factored form: (x + a1)(x + a2)...(x + an) or in expanded form:
b1*x^n + b2*x^n-1 + ... + bn.
This function can be used to find the coefficients within the expanded form of a polynomial given its factored form.
Given the list of solutions to the polynomial when it is set to equal 0  (i.e. a1 ... an in the factored form above),
this function returns the list of coefficients within the expanded form (b1 ... bn in the expanded form above).
"""

def get_polynomial_coefficients(numbers) -> list:
    coefficients = []
    for i in range(len(numbers), 0, -1):
        total = 0
        for combination in combinations(numbers, i):
            total += reduce(operator.mul, combination, 1)
        coefficients.append(total)
    return coefficients

""""
Function specifically for calculating the HS polynomial within SignOut and Verify
"""

def calculate_Hs_polynomial(attributes, hi) -> int:
    Hs_b_coefficients = get_polynomial_coefficients(attributes)
    Hs_b_coefficients.append(1)
    return reduce(operator.mul, [hi[i] * Hs_b_coefficients[i] for i in range(len(Hs_b_coefficients))], 1)


"""
Aggregate algorithm taken from the conference paper: Fully Collusion Secure Dynamic Broadcast Encryption with 
Constant-Size Ciphertexts or Decryption Keys authored by Pascal Paillier and David Pointcheval.
"""


def aggregate(x_array, p_array) -> int:
    p_array = list(p_array)
    if len(x_array) != len(p_array):
        return -1
    r = len(x_array)
    for j in range(r - 1):
        for l in range(j + 1, r):
            if x_array[j] == x_array[l]:
                return -1
            exponent = 1 / (x_array[l] - x_array[j])
            p_array[l] = (p_array[j] ** exponent) - (p_array[l] ** exponent)
    return p_array[r - 1]


def main():

    # The security level of the system. Must be divisible by 8 and > 0 and <= 512
    security_parameter = 8

    # Choose one of the following elliptic curve groups to use
    group = PairingGroup('SS512')
    p = 730750818665451621361119245571504901405976559617

    # group = PairingGroup('SS1024')
    # p = 36203638728584889925158415861634051131656232976339194924022065306723188923966451762160327870969638730567198058600508960697138006366861790409776528385407283664860565239295291314844246909284597617282274074224254733917313218308080644731349763985110821627195514711746037056425804819692632040479575042834043863089

    chariot = Chariot(group, p, security_parameter)

    attribute_universe = list([i for i in range(10)])  # All possible attributes that can be used
    attribute_set = [i for i in range(8)]  # Attributes of the device

    # Upper bound on policy sizes
    # Choose some value > len(attribute_set)
    n = len(attribute_universe)

    # Threshold value
    # At least this many attributes must be matching between the device and the policy
    t = 6

    policy = [i for i in range(7)]  # The attributes that the device must have to be authenticated

    threshold_policy = ThresholdPolicy(t, policy)

    message = "abcd"  # Message to be signed. Choose some string.
    output = chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)
    print(f"Authentication succeeded: {output}")


if __name__ == '__main__':
    main()