import unittest
import operator
from functools import reduce
from charm.schemes.CHARIOT.chariot import get_polynomial_coefficients


class TestPolynomial(unittest.TestCase):

    def test_calculate_correct_polynomial_coefficients(self):
        polynomial_coefficients = get_polynomial_coefficients([1, 2])
        x = 3
        factored_form = (x + 1) * (x + 2)
        expanded_form = polynomial_coefficients[0] + x * polynomial_coefficients[1] + x ** 2
        self.assertEqual(factored_form, expanded_form)

    def test_calculate_correct_polynomial_coefficients2(self):
        numbers = [-2, 4, 5, -1]
        polynomial_coefficients = get_polynomial_coefficients(numbers)
        x = 5
        factored_form = reduce(operator.mul, [x + num for num in numbers])
        expanded_form = x ** 4 + reduce(
            operator.add,
            [coefficient * x ** i for i, coefficient in enumerate(polynomial_coefficients)])

        self.assertEqual(factored_form, expanded_form)



if __name__ == "__main__":
    unittest.main()