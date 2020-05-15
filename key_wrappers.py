from dataclasses import dataclass

@dataclass
class MasterSecretKey:
    def __init__(self, alpha, beta, gamma):
        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma

@dataclass
class OutsourcingKey:
    g1: list
    h1: list
    h2: list
    g2: list
    hashed_attributes: list


@dataclass
class PrivateKey:
    h: int
    K: int

@dataclass
class SecretKey:
    K: int
