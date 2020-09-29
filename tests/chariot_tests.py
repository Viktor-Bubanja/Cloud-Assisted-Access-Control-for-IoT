import unittest
from charm.schemes.CHARIOT.chariot import Chariot
from charm.schemes.CHARIOT.exceptions.not_enough_matching_attributes import NotEnoughMatchingAttributes
from charm.schemes.CHARIOT.wrapper_classes.threshold_policy import ThresholdPolicy
from charm.toolbox.pairinggroup import PairingGroup

group = PairingGroup('SS512')
p = 730750818665451621361119245571504901405976559617

class TestChariot(unittest.TestCase):

    def test_valid_input_successfully_authenticates(self):
        chariot = Chariot(group, p, k)
        attribute_set = [i for i in range(6)]
        policy = {i for i in range(6)}
        threshold_policy = ThresholdPolicy(t, policy)
        message = "abcd"
        output = chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)
        self.assertTrue(output)

    def test_too_few_matching_attributes_raises_exception(self):
        with self.assertRaises(NotEnoughMatchingAttributes):
            chariot = Chariot(group, p, k)
            attribute_set = [1 for _ in range(6)]
            policy = {i for i in range(6)}
            threshold_policy = ThresholdPolicy(t, policy)
            message = "abcd"
            chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)

    def test_too_few_attributes_raises_exception(self):
        with self.assertRaises(NotEnoughMatchingAttributes):
            chariot = Chariot(group, p, k)
            attribute_set = [1, 2, 3]
            policy = {i for i in range(6)}
            threshold_policy = ThresholdPolicy(t, policy)
            message = "abcd"
            chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)


if __name__ == "__main__":
    k = 16
    t = 6
    attribute_universe = list([i for i in range(20)])
    n = len(attribute_universe)
    unittest.main()
