from charm.schemes.CHARIOT.public_params import PublicParams


class Commitment:
    def __init__(self, r_theta: int, s_theta: int, params: PublicParams):
        self.r_theta = r_theta
        self.s_theta = s_theta
        self.params = params

    def calculate(self, theta):
        return tuple([
            self.params.g1[0] ** self.r_theta,
            self.params.g2[1] ** self.s_theta,
            theta * (self.params.g1[2] ** self.r_theta) * (self.params.g2[2] ** self.s_theta)
        ])