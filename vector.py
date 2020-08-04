class Vector:
    def __init__(self, vector: list):
        self.vector = vector

    # Element-wise multiplication
    def dot(self, v2):
        assert len(self.vector) == len(v2)
        return Vector([i * j for i, j in zip(self.vector, v2)])

    # Element-wise exponentiation
    def power(self, exponent):
        return Vector([v ** exponent for v in self.vector])