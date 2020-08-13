from dataclasses import dataclass
from charm.schemes.CHARIOT.vector import Vector
import hashlib

# class PublicParams:
#     def __init__(self, security_param, attribute_universe, n, g, h, u, vi, hi, g1, g2, g3, hash_function):
#         self.security_param = security_param
#         self.attribute_universe = attribute_universe
#         self.n = n
#         self.g = g
#         self.h = h
#         self.u = u
#         self.vi = vi
#         self.hi = hi
#         self.g1 = g1
#         self.g2 = g2
#         self.g3 = g3
#         self.hash_function = hash_function


@dataclass
class PublicParams:
    security_param: int
    attribute_universe: set
    n: int
    g: int
    h: int
    u: int
    vi: list
    hi: list
    g1: Vector
    g2: Vector
    g3: list

