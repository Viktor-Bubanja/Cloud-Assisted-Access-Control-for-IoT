import unittest
import operator
from functools import reduce

from charm.schemes.CHARIOT.chariot import aggregate, Chariot
from charm.toolbox.pairinggroup import ZR, G1, PairingGroup

group = PairingGroup('SS512')
p = 730750818665451621361119245571504901405976559617
k = 16
t = 6
attribute_universe = list([i for i in range(20)])
n = len(attribute_universe)
chariot = Chariot(group, p, k)
class TestAggregate(unittest.TestCase):

    def test_aggregate_calculates_correct_value(self):
        r = 5
        g = group.random(G1)
        gamma = group.random(ZR)
        x_array = [group.random(ZR), group.random(ZR), group.random(ZR)]
        p_array = [g ** (r / (gamma + i)) for i in x_array]
        output = aggregate(x_array, p_array)
        expected_output = g ** (r / reduce(operator.mul, [gamma + i for i in x_array], 1))
        self.assertEqual(output, expected_output)
