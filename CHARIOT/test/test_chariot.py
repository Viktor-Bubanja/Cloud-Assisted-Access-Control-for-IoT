import unittest
from charm.schemes.CHARIOT.chariot import Chariot
from charm.schemes.CHARIOT.exceptions.invalid_attribute_found import InvalidAttributeFound
from charm.schemes.CHARIOT.exceptions.not_enough_matching_attributes import NotEnoughMatchingAttributes
from charm.schemes.CHARIOT.wrapper_classes.key_wrappers import PrivateKey
from charm.schemes.CHARIOT.wrapper_classes.threshold_policy import ThresholdPolicy
from charm.toolbox.pairinggroup import PairingGroup

group = PairingGroup('SS512')
p = 730750818665451621361119245571504901405976559617
k = 16
t = 6
attribute_universe = list([i for i in range(20)])
n = len(attribute_universe)
chariot = Chariot(group, p, k)

class TestChariot(unittest.TestCase):

    def test_t_equal_to_size_of_policy_succeeds(self):
        attribute_set = [i for i in range(6)]
        policy = [i for i in range(6)]
        threshold_policy = ThresholdPolicy(t, policy)
        message = "abcd"
        output = chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)
        self.assertTrue(output)

    def test_t_smaller_than_size_of_policy_succeeds(self):
        attribute_set = [i for i in range(6)]
        policy = [i for i in range(6)]
        t = 2
        threshold_policy = ThresholdPolicy(t, policy)
        message = "abcd"
        output = chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)
        self.assertTrue(output)

    def test_attribute_set_bigger_than_policy_succeeds(self):
        attribute_set = [i for i in range(10)]
        policy = [i for i in range(6)]
        t = 3
        threshold_policy = ThresholdPolicy(t, policy)
        message = "abcd"
        output = chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)
        self.assertTrue(output)

    def test_too_few_matching_attributes_raises_exception(self):
        with self.assertRaises(NotEnoughMatchingAttributes):
            attribute_set = [1 for _ in range(6)]
            policy = [i for i in range(6)]
            threshold_policy = ThresholdPolicy(t, policy)
            message = "abcd"
            chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)

    def test_too_few_attributes_raises_exception(self):
        with self.assertRaises(NotEnoughMatchingAttributes):
            attribute_set = [1, 2, 3]
            policy = [i for i in range(6)]
            threshold_policy = ThresholdPolicy(t, policy)
            message = "abcd"
            chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)

    def test_empty_message_succeeds(self):
        attribute_set = [i for i in range(10)]
        policy = [i for i in range(6)]
        threshold_policy = ThresholdPolicy(t, policy)
        message = ""
        output = chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)
        self.assertTrue(output)

    def test_negative_attributes_raises_exception(self):
        with self.assertRaises(InvalidAttributeFound):
            attribute_set = [-i for i in range(10)]
            policy = [-i for i in range(6)]
            threshold_policy = ThresholdPolicy(t, policy)
            message = "asdfd"
            output = chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)
            self.assertTrue(output)

    def test_attribute_not_in_attribute_universe_raises_exception(self):
        with self.assertRaises(InvalidAttributeFound):
            t = 2
            attribute_set = [i for i in range(10)]
            attribute_set[-1] = 1000
            policy = [i for i in range(6)]
            threshold_policy = ThresholdPolicy(t, policy)
            message = "asdfd"
            output = chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)
            self.assertTrue(output)

    def test_attribute_in_policy_not_in_attribute_universe_raises_exception(self):
        with self.assertRaises(InvalidAttributeFound):
            t = 2
            attribute_set = [i for i in range(10)]
            policy = [i for i in range(6)]
            policy[-1] = 1000
            threshold_policy = ThresholdPolicy(t, policy)
            message = "asdfd"
            output = chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)
            self.assertTrue(output)

    def test_alternate_elliptic_curve_group(self):
        group = PairingGroup('SS1024')
        p = 36203638728584889925158415861634051131656232976339194924022065306723188923966451762160327870969638730567198058600508960697138006366861790409776528385407283664860565239295291314844246909284597617282274074224254733917313218308080644731349763985110821627195514711746037056425804819692632040479575042834043863089
        chariot = Chariot(group, p, k)
        attribute_set = [i for i in range(3)]
        policy = [i for i in range(2)]
        t = 2
        threshold_policy = ThresholdPolicy(t, policy)
        message = "abcd"
        output = chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)
        self.assertTrue(output)

    def test_reverse_order_attribute_set_succeeds(self):
        attribute_set = [i for i in range(6, -1, -1)]
        policy = [i for i in range(6)]
        threshold_policy = ThresholdPolicy(t, policy)
        message = "abcd"
        output = chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)
        self.assertTrue(output)

    def test_reverse_order_policy_succeeds(self):
        attribute_set = [i for i in range(6)]
        policy = [i for i in range(6, -1, -1)]
        threshold_policy = ThresholdPolicy(t, policy)
        message = "abcd"
        output = chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)
        self.assertTrue(output)

    def test_k_non_divisible_by_8_throws_exception(self):
        with self.assertRaises(Exception):
            Chariot(group, p, 10)

    def test_k_too_big_throws_exception(self):
        with self.assertRaises(Exception):
            Chariot(group, p, 513)

    def test_k_upper_edge_case_succeeds(self):
        k = 512
        chariot = Chariot(group, p, k)
        attribute_set = [i for i in range(6)]
        policy = [i for i in range(6)]
        threshold_policy = ThresholdPolicy(t, policy)
        message = "abcd"
        output = chariot.call(attribute_universe, attribute_set, threshold_policy, message, n)
        self.assertTrue(output)

    def test_keygen_hashes_attributes(self):
        attribute_set = [i for i in range(6)]
        params, msk = chariot.setup(attribute_universe, n)
        osk, private_key, _ = chariot.keygen(params, msk, attribute_set)
        print(private_key)
        self.assertNotEqual(osk.hashed_attributes, attribute_set)

    def test_keygen_private_key_h_is_Element(self):
        attribute_set = [i for i in range(6)]
        params, msk = chariot.setup(attribute_universe, n)
        osk, private_key, _ = chariot.keygen(params, msk, attribute_set)
        self.assertTrue(group.ismember(private_key.h))

    def test_request_keeps_same_threshold(self):
        threshold = 5
        policy = ThresholdPolicy(threshold, [])
        threshold_policy = chariot.request(policy, PrivateKey(0, 0))
        self.assertEqual(threshold, threshold_policy.threshold)

    def test_noisy_communication_fails_equality_check(self):
        attribute_set = [i for i in range(6)]
        policy_attributes = [i for i in range(6)]
        policy = ThresholdPolicy(t, policy_attributes)
        message = "sgsf"
        public_params, master_secret_key = chariot.setup(attribute_universe, n)
        osk, private_key, secret_key = chariot.keygen(public_params, master_secret_key, attribute_set)
        HMAC_hashed_threshold_policy = chariot.request(policy, private_key)
        outsourced_signature = chariot.sign_out(public_params, osk, HMAC_hashed_threshold_policy)
        signature = chariot.sign(public_params, private_key, message, outsourced_signature)
        noise = 1
        # Adding noise to the transferred secret key
        # i.e. Simulating a noisy signal
        secret_key.K += noise
        verified = chariot.verify(public_params, secret_key, message, signature, policy)
        self.assertNotEqual(0, verified)


    def test_k_equal_0_throws_exception(self):
        with self.assertRaises(Exception):
            Chariot(group, p, 0)



if __name__ == "__main__":
    unittest.main()
