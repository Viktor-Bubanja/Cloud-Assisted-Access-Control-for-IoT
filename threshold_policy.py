from dataclasses import dataclass

@dataclass
class ThresholdPolicy:
    threshold: int
    policy: set
