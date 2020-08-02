from dataclasses import dataclass
from charm.schemes.CHARIOT.commitment import Commitment
from charm.schemes.CHARIOT.vector import Vector


@dataclass
class OutsourcedSignature:
    C_T1_dash: Commitment
    C_T2_dash: Commitment
    C_theta_dash: Commitment
    pi_1_dash: Vector
    pi_2_dash: Vector
    T2_dash: int
    Hs: int
    g_r: int
    g_s: int


@dataclass
class Signature:
    C_T1: Commitment
    C_T2: Commitment
    C_theta: Commitment
    pi_1: Vector
    pi_2: Vector
