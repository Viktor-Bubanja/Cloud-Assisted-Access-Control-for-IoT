from charm.schemes.CHARIOT.vector import Vector


class Commitment:
    def __init__(self, r_theta: int, s_theta: int, theta: int, g1: Vector, g2: Vector):
        self.r_theta = r_theta
        self.s_theta = s_theta
        self.g1 = g1
        self.g2 = g2
        self.theta = theta

    def calculate(self):
        return Vector([1, 1, self.theta]).dot(self.g1.exp(self.r_theta)).dot(self.g2.exp(self.s_theta))

    def __getitem__(self, key):
        if key < 0 or key > 2:
            raise IndexError
        return self.theta[key]
