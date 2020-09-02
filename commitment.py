from charm.schemes.CHARIOT.vector import Vector


class Commitment:
    def __init__(self, c1, c2, r_theta: int, s_theta: int, theta: int, g1: Vector, g2: Vector):
        self.c1 = c1
        self.c2 = c2
        self.r_theta = r_theta
        self.s_theta = s_theta
        self.g1 = g1
        self.g2 = g2
        self.theta = theta

    def calculate(self) -> Vector:
        return Vector([self.g1[0] ** self.r_theta,
                       self.g2[1] ** self.s_theta,
                       self.theta * (self.g1[2] ** self.r_theta) * (self.g2[2] ** self.s_theta)])
        # return Vector([self.c1, self.c2, self.theta]).dot(self.g1.exp(self.r_theta)).dot(self.g2.exp(self.s_theta))

    def __getitem__(self, key):
        if key < 0 or key > 2:
            raise IndexError
        return self.calculate()[key]
