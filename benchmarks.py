import time

from charm.schemes.CHARIOT.chariot import Chariot
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
    group = PairingGroup('SS512')
    chariot = Chariot(group)
    benchmark_setup(chariot)
    benchmark_keygen(chariot)

