class MasterSecretKey:
    def __init__(self, alpha, beta, gamma):
        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma


class OutsourcingKey:
    def __init__(self, g1, h1, h2, g2):
        self.g1 = g1
        self.h1 = h1
        self.h2 = h2
        self.g2 = g2


class PrivateKey:
    def __init__(self, h, K):
        self.h = h
        self.K = K


class SecretKey:
    def __init__(self, K):
        self.K = K
