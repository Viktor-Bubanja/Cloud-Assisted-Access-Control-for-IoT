import sys
import hmac
import operator

from charm.schemes.CHARIOT.commitment import Commitment
from charm.schemes.CHARIOT.exceptions import NotEnoughMatchingAttributes, EqualityDoesNotHold
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

p = 730750818665451621361119245571504901405976559617



class Chariot:
    s, t = 0, 0
    Fs_minus_omega_polynomial = 0  # TODO delete
    F_omega_polynomial = 0
    alpha = 0
    gamma = 366866851579218089005170006376467776307359864376
    r = 0
    outsourcing_key = 0
    T2_b_coefficients = 0
    product2 = 0
    product1 = 0
    infinite_element = 0

    def __init__(self, group, k):
        assert k % 8 == 0
        self.group = group
        self.k = k


    def setup(self, security_param, attribute_universe, n) -> (PublicParams, MasterSecretKey):
        # Let g, h be two generators of G.
        # TODO Should h be from G1 or G2? G1 works fine, G2 causes problems
        g, h = self.group.random(G1), self.group.random(G1)
        alpha, beta, gamma = self.group.random(ZR), self.group.random(ZR), self.group.random(ZR)
        gamma = self.group.init(ZR, 366866851579218089005170006376467776307359864376)
        self.alpha = alpha # TODO delete
        self.gamma = gamma # TODO delete

        self.infinite_element = self.group.random(G1) ** p

        u = g ** beta
        vi = [g ** (alpha / (gamma ** i)) for i in range(n + 1)]
        hi = [h ** (alpha * (gamma ** i)) for i in range(n + 1)]

        generator1 = self.group.random(G1)
        generator2 = self.group.random(G2)

        g1 = Vector([generator1, self.group.random(G1) ** p, g])
        g2 = Vector([self.group.random(G1) ** p, generator2, g])
        # g1 = Vector([generator1, 1, g])
        # g2 = Vector([1, generator2, g])
        g3 = []

        for i in range(self.k + 1):
            xi1, xi2 = self.group.random(ZR), self.group.random(ZR)
            g3.append([generator1 ** xi1, generator2 ** xi2, g ** (xi1 + xi2)])

        return (PublicParams(security_param=security_param,
                             attribute_universe=attribute_universe,
                             n=n, g=g, h=h, u=u, vi=vi, hi=hi, g1=g1, g2=g2, g3=g3),
                MasterSecretKey(alpha=alpha, beta=beta, gamma=gamma))

    def keygen(self, params, msk, attributes) -> (OutsourcingKey, PrivateKey, SecretKey):
        K = 10  # TODO check secret key
        beta1 = self.group.random()
        beta2 = msk.beta + beta1
        r = self.group.random(ZR)
        self.r = r

        hashed_attributes = tuple([self.calculate_HMAC(K, at) for at in attributes])

        osk_g1 = tuple([params.g ** (r / (msk.gamma + hashed_attribute))
                        for hashed_attribute in hashed_attributes])

        osk_g2 = params.g ** beta1

        osk_h1 = tuple([params.h ** (r * (msk.gamma ** i)) for i in range(1, params.n)])

        osk_h2 = params.h ** ((r - beta2) * (msk.gamma ** params.n))

        sk_h1 = params.h ** (beta1 * (msk.gamma ** params.n))

        self.outsourcing_key = OutsourcingKey(g1=osk_g1, g2=osk_g2, h1=osk_h1, h2=osk_h2, hashed_attributes=hashed_attributes)

        return (OutsourcingKey(g1=osk_g1, g2=osk_g2, h1=osk_h1, h2=osk_h2, hashed_attributes=hashed_attributes),
                PrivateKey(sk_h1, K),
                SecretKey(K))

    def request(self, signing_policy: ThresholdPolicy, private_key: PrivateKey) -> ThresholdPolicy:
        # Need to store t and s on the IoT device to perform the Sign algorithm later.
        self.t = signing_policy.threshold
        policy = signing_policy.policy
        self.s = len(policy)

        K = private_key.K
        hashed_policy = set([self.calculate_HMAC(K, at) for at in policy])
        return ThresholdPolicy(threshold=self.t, policy=hashed_policy)

    def sign_out(self, params: PublicParams, osk: OutsourcingKey,
                 threshold_policy: ThresholdPolicy) -> OutsourcedSignature:
        s = len(threshold_policy.policy)
        t = threshold_policy.threshold
        common_attributes = [at for at in threshold_policy.policy if at in osk.hashed_attributes]
        if len(common_attributes) < t:
            raise NotEnoughMatchingAttributes

        # Find some set of size t of common attributes
        common_attributes = common_attributes[:t]
        # T1 = self.aggregate(osk.g1, list(osk.hashed_attributes))  # TODO uncomment later.



        F_common_at_polynomial = reduce(
            operator.mul,
            [self.gamma + at for at in common_attributes]
        )

        T1 = params.g ** (self.r / F_common_at_polynomial)


        remaining_attributes = [at for at in threshold_policy.policy if at not in common_attributes]

        F_coefficients = get_polynomial_coefficients(common_attributes)
        F_coefficients.append(1)
        self.F_omega_polynomial = reduce(
            operator.mul,
            [(self.gamma ** i) * F_coefficients[i] for i in range(len(F_coefficients))]
        )  # TODO delete

        T2_b_coefficients = get_polynomial_coefficients(remaining_attributes)
        T2_b_coefficients.append(1)
        self.T2_b_coefficients = T2_b_coefficients  # TODO delete
        gamma_squared = self.gamma ** 2
        sum_list = [(self.gamma ** i) * T2_b_coefficients[i] for i in range(len(T2_b_coefficients))]

        multiply_list = [self.gamma + at for at in remaining_attributes]

        # summation
        self.Fs_minus_omega_polynomial = reduce(
            operator.add,
            [(self.gamma ** i) * T2_b_coefficients[i] for i in range(len(T2_b_coefficients))]
        )  # TODO delete

        Fs_minus_omega_polynomial_product = reduce(
            operator.mul,
            [self.gamma + at for at in remaining_attributes]
        )




        T2_dash = osk.h2
        for i in range(s - t):
            T2_dash = T2_dash * (osk.h1[i + params.n - s + t - 1] ** T2_b_coefficients[i])




        product1 = reduce(
            operator.mul,
            [self.gamma + at for at in threshold_policy.policy]
        )

        self.product1 = product1

        product2 = reduce(
            operator.mul,
            [self.gamma + at for at in common_attributes]
        )

        self.product2 = product2

        product3 = reduce(
            operator.mul,
            [self.gamma + at for at in remaining_attributes]
        )

        # Hs = self.calculate_polynomial(threshold_policy.policy, params.hi) # TODO Uncomment
        Hs = params.h ** (self.alpha * product1)

        # TODO Testing Hs
        Hs1 = params.h ** (self.alpha * self.product1)
        Hs2 = self.calculate_polynomial(threshold_policy.policy, params.hi) # TODO Uncomment
        Hs_test = Hs1 == Hs2





        lhs = product1 / product2
        rhs = product3


        testing_T1 = params.g ** (self.r / product2)

        next_test_lhs = pair(params.g ** (self.r / product2), params.h ** (self.alpha * product1))
        next_test_rhs = pair(params.g, params.h) ** (self.r * self.alpha * product3)
        test2 = next_test_lhs == next_test_rhs





        equality_term1 = pair(T1, Hs)
        equality_term2 = pair(params.u * osk.g2, params.hi[s - t])
        equality_term3 = pair(T2_dash, params.vi[params.n - s + t])

        if equality_term1 != equality_term2 * equality_term3:
            print()
            # TODO Uncomment below
            raise EqualityDoesNotHold

        r1, s1, r2, s2 = self.group.random(), self.group.random(), self.group.random(), self.group.random()
        r_theta, s_theta = self.group.random(), self.group.random()

        C_T1_dash = Commitment(self.infinite_element, self.infinite_element, r1, s1, T1, params.g1, params.g2)
        C_T2_dash = Commitment(self.infinite_element, self.infinite_element, r2, s2, T2_dash, params.g1, params.g2)

        pi_1_dash_1 = (Hs ** r1) * ((params.u * osk.g2) ** -r_theta) * (params.vi[params.n - s + t] ** -r2)
        pi_1_dash_2 = (Hs ** s1) * ((params.u * osk.g2) ** -s_theta) * (params.vi[params.n - s + t] ** -s2)
        pi_1_dash = Vector([pi_1_dash_1, pi_1_dash_2, 1])

        pi_2_dash = Vector([params.g ** r_theta, params.g ** s_theta, 1])

        g_r = osk.g2 ** r_theta
        g_s = osk.g2 ** s_theta

        C_theta_dash = Commitment(self.infinite_element, self.infinite_element, self.group.random(), self.group.random(), params.hi[s - t], params.g1, params.g2)

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

    def sign(self, params: PublicParams, sk: PrivateKey, message: str,
             outsourced_signature: OutsourcedSignature) -> Signature:
        T2 = outsourced_signature.T2_dash * sk.h
        T1 = outsourced_signature.C_T1_dash.theta


        testing_T1 = params.g ** (self.r / self.F_omega_polynomial)

        # equality_term1 = pair(T1, outsourced_signature.Hs)
        # equality_term2 = pair(params.u, params.hi[self.s - self.t])
        # equality_term3 = pair(T2, params.vi[params.n - self.s + self.t])






        # TODO Testing v[...]. True
        v_lhs = params.vi[params.n - self.s + self.t] ** -1
        g_rhs = params.g ** (-self.alpha / (self.gamma ** (params.n - self.s + self.t)))

        test_lhs = v_lhs == g_rhs



        # TODO Testing T2
        lhs = T2
        rhs_product = reduce(
            operator.mul,
            [self.outsourcing_key.h1[i + params.n - self.s + self.t - 1] ** self.T2_b_coefficients[i]
             for i in range(self.s - self.t)]
        )
        T2_dash_rhs = self.outsourcing_key.h2 * rhs_product
        rhs = T2_dash_rhs * sk.h

        test_T2 = lhs == rhs













        T2_v = pair(T2, params.vi[params.n - self.s + self.t] ** -1)
        T1_h = pair(T1, outsourced_signature.Hs)
        u_h = pair(params.u, params.hi[self.s - self.t])






        # TODO Testing e(T1, h) == e(g**, h**)
        g_rhs = params.g ** (self.r / self.product2)
        h_rhs = params.h ** (self.alpha * self.product1)
        testing3 = T1_h == pair(g_rhs, h_rhs)





        # TODO Testing e(T1, h) == e(g, h)**
        test1 = pair(params.g, params.h) ** (self.alpha * self.r * self.Fs_minus_omega_polynomial)
        testing = T1_h == test1







        lhs = T2_v * T1_h
        rhs = u_h


        if lhs != rhs:
            print()
        else:
            print()

        # if equality_term1 != (equality_term2 * equality_term3):
        #     raise EqualityDoesNotHold
        hashed_message = hash_message(int(self.k / 8), bytes(message, UTF))

        g_3_m = Vector([params.g3[0][0], params.g3[0][1], params.g3[0][2]])

        for mi, gi in zip(hashed_message[1:], params.g3[1:]):
            g_3_m = g_3_m.dot(Vector(gi).exp(int(mi)))

        t1, t2, t_theta = self.group.random(), self.group.random(), self.group.random()

        a = outsourced_signature.C_T1_dash.calculate()
        b = a.dot(g_3_m.exp(t1))

        C_T1 = outsourced_signature.C_T1_dash.calculate().dot(g_3_m.exp(t1))

        C_T2 = outsourced_signature.C_T2_dash.calculate().dot(
            Vector([1, 1, sk.h])).dot(
            g_3_m.exp(t2)
        )

        C_theta = outsourced_signature.C_theta_dash.calculate().dot(g_3_m).exp(t_theta)

        pi_1 = outsourced_signature.pi_1_dash.dot(
            Vector([
                1 / outsourced_signature.g_r,
                1 / outsourced_signature.g_s,
                (outsourced_signature.Hs ** t1) * (params.u ** -t_theta) * (
                            params.vi[params.n - self.s + self.t] ** -t2)
            ])
        )

        pi_2 = outsourced_signature.pi_2_dash.dot(Vector([1, 1, (params.g ** t_theta)]))

        return Signature(C_T1=C_T1, C_T2=C_T2, C_theta=C_theta, pi_1=pi_1, pi_2=pi_2)

    def verify(self, params: PublicParams, secret_key: SecretKey, message: str, signature: Signature,
               threshold_policy: ThresholdPolicy) -> int:
        s = len(threshold_policy.policy)
        t = threshold_policy.threshold

        hashed_message = hash_message(int(self.k / 8), bytes(message, UTF))

        g_3_m = Vector([params.g3[0][0], params.g3[0][1], params.g3[0][2]])
        for mi, gi in zip(hashed_message[1:], params.g3[1:]):
            g_3_m = g_3_m.dot(Vector(gi).exp(int(mi)))

        hashed_policy = set([self.calculate_HMAC(secret_key.K, at) for at in threshold_policy.policy])

        Hs = self.calculate_polynomial(hashed_policy, params.hi)

        pi_1_1, pi_1_2, pi_1_3 = signature.pi_1.elements
        pi_2_1, pi_2_2, pi_2_3 = signature.pi_2.elements

        # First component

        # a = self.group.random(G1) ** p + self.group.init(ZR, 1)

        equality_term1_1 = pair(Hs, signature.C_T1[0])
        equality_term1_2 = pair(params.u, signature.C_theta[0])
        equality_term1_3 = pair(params.vi[params.n - self.s + self.t], signature.C_T2[0])
        equality_term1_4 = pair(pi_1_1, params.g1[0])
        equality_term1_5 = pair(pi_1_2, params.g2[0])
        equality_term1_6 = pair(pi_1_3, g_3_m[0])


        equality_term2_1 = pair(params.g, signature.C_theta)
        equality_term2_2 = pair(params.g, (1, 1, params.hi[s - t]))
        equality_term2_3 = pair(pi_2_1, params.g1)
        equality_term2_4 = pair(pi_2_2, params.g2)
        equality_term2_5 = pair(pi_2_3, g_3_m)

        if equality_term1_1 == (
                equality_term1_2 *
                equality_term1_3 *
                equality_term1_4 *
                equality_term1_5 *
                equality_term1_6) and equality_term2_1 == (
                equality_term2_2 *
                equality_term2_3 *
                equality_term2_4 *
                equality_term2_5):
            return 0
        else:
            return 1

    def calculate_polynomial(self, attributes, hi) -> int:
        Hs_b_coefficients = get_polynomial_coefficients(attributes)
        Hs_b_coefficients.append(1)
        return reduce(operator.mul, [hi[i] * Hs_b_coefficients[i] for i in range(len(Hs_b_coefficients))])

    def aggregate(self, x_array, p_array) -> int:
        if len(x_array) != len(p_array):
            return -1
        r = len(x_array)
        for j in range(r - 1):
            for l in range(j + 1, r):
                if x_array[j] == x_array[l]:
                    return -1
                p_array[l] = (1 / (x_array[l] - x_array[j])) * (p_array[j] - p_array[l])

        return p_array[r - 1]

    def calculate_HMAC(self, secret_key: int, message: int):
        hashed_message = hmac.new(bytes(secret_key), bytes(message), HMAC_HASH_FUNC).digest()
        return self.group.init(ZR, int.from_bytes(hashed_message, byteorder=sys.byteorder))


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
Polynomials can be written in factored form: (x - a1)(x - a2)...(x - an)
or in expanded form: b1*x^n + b2*x^n-1 + ... + bn
This function can be used to find the coefficients within the expanded form
of a polynomial given its factored form.
Given the list of solutions to the polynomial when it is set to equal 0 
(i.e. a1 ... an in the factored form above), this function returns the list
of coefficients within the expanded form (b1 ... bn in the expanded form above)"""
def get_polynomial_coefficients(numbers) -> list:
    coefficients = []
    for i in range(len(numbers), 0, -1):
        total = 0
        for combination in combinations(numbers, i):
            total += reduce(operator.mul, combination, 1)
        coefficients.append(total)
    return coefficients
