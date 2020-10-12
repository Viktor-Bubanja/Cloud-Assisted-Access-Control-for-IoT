import unittest

from charm.schemes.CHARIOT.vector import Vector


class TestChariot(unittest.TestCase):

    def test_vector_dot_product(self):
        vector1 = Vector([1, 2, 3])
        vector2 = Vector([2, 3, 4])
        dot_product = vector1.dot(vector2)
        self.assertEqual(dot_product, Vector([2, 6, 12]))

    def test_vector_first_index_correctly_retrieved(self):
        vector = Vector([1, 2, 3])
        self.assertEqual(1, vector[0])

    def test_vector_second_index_correctly_retrieved(self):
        vector = Vector([1, 2, 3])
        self.assertEqual(2, vector[1])

    def test_vector_third_index_correctly_retrieved(self):
        vector = Vector([1, 2, 3])
        self.assertEqual(3, vector[2])

    def test_two_equal_vectors(self):
        vector1 = Vector([1, 2, 3])
        vector2 = Vector([1, 2, 3])
        self.assertTrue(vector1 == vector2)
