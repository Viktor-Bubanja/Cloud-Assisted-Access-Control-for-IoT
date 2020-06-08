from dataclasses import dataclass
from charm.schemes.CHARIOT.commitment import Commitment


@dataclass
class OutsourcedSignature:
    C_T1_dash: tuple
    C_T2_dash: tuple
    C_theta_dash: Commitment
    pi_1_dash: tuple
    pi_2_dash: tuple
    T2_dash: int
    Hs: int
    g_r: int
    g_s: int