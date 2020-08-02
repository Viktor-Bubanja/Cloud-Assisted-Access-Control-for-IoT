class Vector:
    def __init__(self, v1: list):
        self.v1 = v1

    # Element-wise multiplication
    def dot(self, v2):
        assert len(self.v1) == len(v2)
        return Vector([i * j for i, j in zip(self.v1, v2)])

    # Element-wise exponentiation
    def power(self, exponent):
        return Vector([v ** exponent for v in self.v1])