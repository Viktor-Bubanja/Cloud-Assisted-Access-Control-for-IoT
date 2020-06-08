from dataclasses import dataclass


@dataclass
class MasterSecretKey:
    alpha: int
    beta: int
    gamma: int

@dataclass
class OutsourcingKey:
    g1: tuple
    h1: tuple
    h2: int
    g2: int
    hashed_attributes: tuple


@dataclass
class PrivateKey:
    h: int
    K: int

@dataclass
class SecretKey:
    K: int


