import unittest

from charm.schemes.CHARIOT.commitment import Commitment
from charm.schemes.CHARIOT.vector import Vector


class TestCommitment(unittest.TestCase):

    def test_correctly_calculates_and_stores_value(self):
        r_theta = 2
        s_theta = 3
        theta = 5
        g1 = Vector([2, 3, 4])
        g2 = Vector([1, 1, 1])
        commitment = Commitment(r_theta, s_theta, theta, g1, g2)
        element1 = g1.elements[0] ** r_theta
        element2 = g2.elements[1] ** s_theta
        element3 = theta * (g1[2] ** r_theta) * (g2[2] ** s_theta)
        self.assertEqual(commitment.value, Vector([element1, element2, element3]))

    def test_correctly_retrieves_first_index(self):
        r_theta = 2
        s_theta = 3
        theta = 5
        g1 = Vector([2, 3, 4])
        g2 = Vector([1, 1, 1])
        commitment = Commitment(r_theta, s_theta, theta, g1, g2)
        output = commitment.calculate()
        self.assertEqual(output[0], commitment[0])

    def test_correctly_retrieves_second_index(self):
        r_theta = 2
        s_theta = 3
        theta = 5
        g1 = Vector([2, 3, 4])
        g2 = Vector([1, 1, 1])
        commitment = Commitment(r_theta, s_theta, theta, g1, g2)
        output = commitment.calculate()
        self.assertEqual(output[1], commitment[1])

    def test_correctly_retrieves_third_index(self):
        r_theta = 2
        s_theta = 3
        theta = 5
        g1 = Vector([2, 3, 4])
        g2 = Vector([1, 1, 1])
        commitment = Commitment(r_theta, s_theta, theta, g1, g2)
        output = commitment.calculate()
        self.assertEqual(output[2], commitment[2])