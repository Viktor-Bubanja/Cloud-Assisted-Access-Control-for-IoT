class Vector:
    def __init__(self, elements: list):
        self.elements = elements

    # Element-wise multiplication
    def dot(self, v2):
        assert len(self.elements) == len(v2.elements)
        return Vector([i * j for i, j in zip(self.elements, v2.elements)])

    # Element-wise exponentiation
    def exp(self, exponent):
        return Vector([v ** exponent for v in self.elements])

    def __getitem__(self, key):
        return self.elements[key]

    def __eq__(self, other):
        return self.elements == other.elements
