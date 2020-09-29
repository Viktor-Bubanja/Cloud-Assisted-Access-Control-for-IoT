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


def elliptic_curve1():
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

def elliptic_curve2():
    group = PairingGroup('SS1024')
    p = 36203638728584889925158415861634051131656232976339194924022065306723188923966451762160327870969638730567198058600508960697138006366861790409776528385407283664860565239295291314844246909284597617282274074224254733917313218308080644731349763985110821627195514711746037056425804819692632040479575042834043863089
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

def perform_bencharks(repetitions, security_parameter, attribute_universe, attribute_set, threshold_policy):
    # elliptic_curve1()
    elliptic_curve2()


if __name__ == '__main__':
    repetitions = 10

    attribute_universe = list([i for i in range(16)])
    security_parameter = 8
    attribute_set = [i for i in range(16)]
    t = 8
    policy = {i for i in range(8)}

    threshold_policy = ThresholdPolicy(t, policy)

    perform_bencharks(repetitions, security_parameter, attribute_universe, attribute_set, threshold_policy)








