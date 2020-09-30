import unittest
from charm.schemes.CHARIOT.chariot import Chariot
from charm.schemes.CHARIOT.exceptions.not_enough_matching_attributes import NotEnoughMatchingAttributes
from charm.schemes.CHARIOT.wrapper_classes.threshold_policy import ThresholdPolicy
from charm.toolbox.pairinggroup import PairingGroup

group = PairingGroup('SS512')
p = 730750818665451621361119245571504901405976559617
k = 16
attribute_universe = list([i for i in range(20)])
n = len(attribute_universe)

class TestChariot(unittest.TestCase):

    def test_t_equal_to_size_of_policy_successfully_authenticates(self):
        chariot = Chariot(group, p, k)
        attribute_set = [i for i in range(6)]
        policy = [i for i in range(6)]
        t = 6
        threshold_policy = ThresholdPolicy(t, policy)
        message = "abcd"
        output = chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)
        self.assertTrue(output)

    def test_t_smaller_than_size_of_policy_successfully_authenticates(self):
        chariot = Chariot(group, p, k)
        attribute_set = [i for i in range(6)]
        policy = [i for i in range(6)]
        t = 2
        threshold_policy = ThresholdPolicy(t, policy)
        message = "abcd"
        output = chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)
        self.assertTrue(output)

    def test_attribute_set_bigger_than_policy_successfully_authenticates(self):
        chariot = Chariot(group, p, k)
        attribute_set = [i for i in range(10)]
        policy = [i for i in range(6)]
        t = 3
        threshold_policy = ThresholdPolicy(t, policy)
        message = "abcd"
        output = chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)
        self.assertTrue(output)

    def test_too_few_matching_attributes_raises_exception(self):
        with self.assertRaises(NotEnoughMatchingAttributes):
            chariot = Chariot(group, p, k)
            attribute_set = [1 for _ in range(6)]
            policy = [i for i in range(6)]
            t = 6
            threshold_policy = ThresholdPolicy(t, policy)
            message = "abcd"
            chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)

    def test_too_few_attributes_raises_exception(self):
        with self.assertRaises(NotEnoughMatchingAttributes):
            chariot = Chariot(group, p, k)
            attribute_set = [1, 2, 3]
            policy = [i for i in range(6)]
            t = 6
            threshold_policy = ThresholdPolicy(t, policy)
            message = "abcd"
            chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)

    def test_empty_message_successfully_authenticates(self):
        chariot = Chariot(group, p, k)
        attribute_set = [i for i in range(10)]
        policy = [i for i in range(6)]
        t = 6
        threshold_policy = ThresholdPolicy(t, policy)
        message = ""
        output = chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)
        self.assertTrue(output)

    def test_k_non_divisible_by_8_throws_exception(self):
        with self.assertRaises(Exception):
            Chariot(group, p, 10)

    def test_k_too_big_throws_exception(self):
        with self.assertRaises(Exception):
            Chariot(group, p, 513)

    def test_k_equal_0_throws_exception(self):
        with self.assertRaises(Exception):
            Chariot(group, p, 0)



if __name__ == "__main__":
    unittest.main()
