import time

from charm.schemes.CHARIOT.chariot import Chariot
from charm.schemes.CHARIOT.wrapper_classes.threshold_policy import ThresholdPolicy
from charm.toolbox.pairinggroup import PairingGroup


def benchmark(repetitions, method, *args):
    total_time = 0
    for i in range(repetitions):
        start = time.process_time()
        result = method(*args)
        total_time += time.process_time() - start
    return total_time / repetitions, result


def perform_bencharks(repetitions, security_parameter, attribute_universe, attribute_set, threshold_policy):
    group = PairingGroup('SS512')
    p = 730750818665451621361119245571504901405976559617
    chariot = Chariot(group, p, security_parameter)
    n = len(attribute_universe)  # Upper bound of size of threshold policies

    avg_time, (public_params, master_secret_key) = benchmark(repetitions, chariot.setup, attribute_universe, n)
    print(f"Average Setup time: {avg_time}")

    avg_time, (osk, private_key, secret_key) = benchmark(repetitions, chariot.keygen, public_params, master_secret_key,
                                                         attribute_set)
    print(f"Average Keygen time: {avg_time}")

    avg_time, HMAC_hashed_threshold_policy = benchmark(repetitions, chariot.request, threshold_policy, private_key)
    print(f"Average Request time: {avg_time}")

    avg_time, outsourced_signature = benchmark(repetitions, chariot.sign_out, public_params, osk,
                                               HMAC_hashed_threshold_policy)
    print(f"Average SignOut time: {avg_time}")

    message = "abcd"
    avg_time, signature = benchmark(repetitions, chariot.sign, public_params, private_key, message,
                                    outsourced_signature)
    print(f"Average Sign time: {avg_time}")

    avg_time, output = benchmark(repetitions, chariot.verify, public_params, secret_key, message, signature,
                                 threshold_policy)
    print(f"Average Verify time: {avg_time}")


if __name__ == '__main__':
    repetitions = 1

    attribute_universe = list([i for i in range(10)])
    security_parameter = 8
    attribute_set = [i for i in range(8)]
    t = 6
    policy = [i for i in range(7)]

    threshold_policy = ThresholdPolicy(t, policy)

    perform_bencharks(
        repetitions=repetitions,
        security_parameter=security_parameter,
        attribute_universe=attribute_universe,
        attribute_set=attribute_set,
        threshold_policy=threshold_policy)
