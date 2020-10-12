import unittest

from charm.schemes.CHARIOT.chariot import hash_message


class TestHash(unittest.TestCase):

    def test_hash_outputs_k_bits(self):
        num_bytes = 2
        num_bits = 2 * 8
        output = hash_message(num_bytes, bytes("test", "utf-8"))
        self.assertEqual(len(output), num_bits)

    def test_hash_outputs_type_string(self):
        output = hash_message(2, bytes("random string", "utf-8"))
        self.assertIsInstance(output, str)

    def test_hash_outputs_k_1s_and_0s(self):
        output = hash_message(2, bytes("testing string", "utf-8"))
        self.assertEqual({'0', '1'}, set(list(output)))


if __name__ == '__main__':
    unittest.main()