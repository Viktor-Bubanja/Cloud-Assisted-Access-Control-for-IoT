import time

from charm.schemes.CHARIOT.chariot import Chariot
from charm.schemes.CHARIOT.exceptions import EqualityDoesNotHold
from charm.schemes.CHARIOT.threshold_policy import ThresholdPolicy
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair



def benchmark(repetitions, method, *args):
    total_time = 0
    for i in range(repetitions):
        start = time.process_time()
        method(*args)
        total_time += time.process_time() - start
    return total_time / repetitions


def benchmark_setup(chariot):
    repetitions = 20
    security_param, universe, upper_bound = 0, None, 5
    average = benchmark(repetitions, chariot.setup, security_param, universe, upper_bound)
    print("average time taken for setup: {:.5f}".format(average))


def benchmark_keygen(chariot):
    public_params, msk = chariot.setup(0, None, 5)
    average = benchmark(20, chariot.keygen, public_params, msk, ["a", "b", "c"])
    print("average time taken for keygen: {:.5f}".format(average))


if __name__ == "__main__":
    fail = True
    for _ in range(1):
        try:
            group = PairingGroup('SS512')
            k = 8
            chariot = Chariot(group, k)
            security_param = 2  # TODO what is this
            attribute_universe = [1, 2, 3, 4]
            n = 4  # Upper bound of size of threshold policies
            public_params, master_secret_key = chariot.setup(security_param, attribute_universe, n)


            attribute_set = [1, 2]
            osk, private_key, secret_key = chariot.keygen(public_params, master_secret_key, attribute_set)


            t = 2
            policy = {1, 2, 3, 4}
            threshold_policy = ThresholdPolicy(t, policy)
            HMAC_hashed_threshold_policy = chariot.request(threshold_policy, private_key)

            outsourced_signature = chariot.sign_out(public_params, osk, HMAC_hashed_threshold_policy)

            message = "123"
            signature = chariot.sign(public_params, private_key, message, outsourced_signature)

            output = chariot.verify(public_params, secret_key, message, signature, threshold_policy)

            fail = False
            break
        except EqualityDoesNotHold:
            pass
    print(f"Algorithm failed: {fail}")





