import time

from charm.schemes.CHARIOT.chariot import Chariot
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair

# Prime number for elliptic curve SS512
p = 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791


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
    chariot = Chariot(group, p, 8)
    benchmark_setup(chariot)
    benchmark_keygen(chariot)

