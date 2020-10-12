# Cloud-Assisted-Access-Control-for-IoT

CHARIOT (Cloud-Assisted Access Control for the Internet of Things) is a policy-based access control protocol suitable for an IoT environment.
Computationally intensive signature generation is offloaded from the IoT device to an untrusted, powerful cloud server. This is vital since IoT devices are severely constrained in memory and computational power.

CHARIOT utilises elliptic curve billinear group pairings, a threshold attribute-based signature (ABS) scheme, and Groth-Sahai non-interactive zero-knowledge proof systems.


## Installation

The CHARIOT implementation utilises Charm, a framework for rapidly prototyping advanced cryptosystems. Charm must be installed for CHARIOT to run. There are install instructions on the Charm Github repository: https://github.com/JHUISI/charm.

Once installed, place the CHARIOT folder within the charm-dev/charm/schemes folder. 


## Running

To run the prototype implementation, run the chariot.py module. To run the benchmarking, run benchmarks/benchmarks.py. To run the tests, right-click on the test folder and click "Run 'Unittests in test'". 
