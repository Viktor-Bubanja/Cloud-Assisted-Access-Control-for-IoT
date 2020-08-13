class Vector:
    def __init__(self, vector: list, modulus: int):
        self.vector = vector
        self.modulus = modulus

    # Element-wise multiplication
    def dot(self, v2):
        assert len(self.vector) == len(v2)
        return Vector([(i * j) % self.modulus for i, j in zip(self.vector, v2)], self.modulus)

    # Element-wise exponentiation
    def exp(self, exponent):
        return Vector([(v ** exponent) % self.modulus for v in self.vector], self.modulus)