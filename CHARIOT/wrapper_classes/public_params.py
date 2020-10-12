from dataclasses import dataclass
from charm.schemes.CHARIOT.vector import Vector

@dataclass
class PublicParams:
    attribute_universe: list
    n: int
    g: int
    h: int
    u: int
    vi: list
    hi: list
    g1: Vector
    g2: Vector
    g3: list
