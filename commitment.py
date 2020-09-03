from charm.schemes.CHARIOT.vector import Vector


class Commitment:
    def __init__(self, r_theta: int, s_theta: int, theta: int, g1: Vector, g2: Vector):
        self.r_theta = r_theta
        self.s_theta = s_theta
        self.g1 = g1
        self.g2 = g2
        self.theta = theta
        self.value = self.calculate()

    def calculate(self) -> Vector:
        return Vector([self.g1[0] ** self.r_theta,
                       self.g2[1] ** self.s_theta,
                       self.theta * (self.g1[2] ** self.r_theta) * (self.g2[2] ** self.s_theta)])

    def __getitem__(self, key):
        return self.calculate()[key]
