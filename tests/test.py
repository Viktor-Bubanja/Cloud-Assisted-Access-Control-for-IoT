from charm.schemes.CHARIOT.chariot import Chariot
from charm.schemes.CHARIOT.wrapper_classes.threshold_policy import ThresholdPolicy
from charm.toolbox.pairinggroup import PairingGroup

def test():
    group = PairingGroup('SS512')
    p = 730750818665451621361119245571504901405976559617
    k = 16
    chariot = Chariot(group, p, k)
    attribute_universe = list([i for i in range(20)])
    attribute_set = [i for i in range(6)]
    n = len(attribute_universe)  # Upper bound of size of threshold policies
    t = 6
    policy = {i for i in range(6)}
    threshold_policy = ThresholdPolicy(t, policy)
    message = "abcd"
    output = chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)
    assert output


if __name__ == "__main__":
    test()
