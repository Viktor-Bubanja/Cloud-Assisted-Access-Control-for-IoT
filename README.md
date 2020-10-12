# Cloud-Assisted-Access-Control-for-IoT

CHARIOT (Cloud-Assisted Access Control for the Internet of Things) is a policy-based access control protocol suitable for an IoT environment.
Computationally intensive signature generation is offloaded from the IoT device to an untrusted, powerful cloud server. This is vital since IoT devices are severely constrained in memory and computational power.

(link to original paper: https://www.researchgate.net/publication/329061206_CHARIOT_Cloud-Assisted_Access_Control_for_the_Internet_of_Things).

This repository contains a prototype implementation of CHARIOT for the purposes of testing, benchmarking, and ultimately validating the protocol.

CHARIOT utilises elliptic curve billinear group pairings, a threshold attribute-based signature (ABS) scheme, and Groth-Sahai non-interactive zero-knowledge proof systems.


## Installation

The CHARIOT implementation utilises Charm, a framework for rapidly prototyping advanced cryptosystems. Charm must be installed for CHARIOT to run. There are install instructions on the Charm Github repository: https://github.com/JHUISI/charm.

Once installed, place the CHARIOT folder within the charm-dev/charm/schemes folder. 


## Running

- To run the prototype implementation, run the chariot.py module.
- To run the benchmarking, run benchmarks/benchmarks.py.
- To run the tests, right-click on the test folder and click "Run 'Unittests in test'". 

### Parameters
The input parameters required to initialise an instance of CHARIOT are: group, p, k.
- Group is a pairing group within Charm that contains an elliptic curve and a pairing function. This is initialised like: group = PairingGroup(X) where X is the name of an elliptic curve offered within Charm. Currently, there are two possible options for super singular elliptic curves (required for symmetric bilinear pairing): 'SS512' and 'SS1024'. Important note: if more super singular elliptic curves become available within Charm in the future, it is essential that elliptic curves with at least 256 bits are chosen because attributes are hashed with SHA256 and the hash of the attributes must be within the base field of the elliptic curve.
- p is the order of the Galois field the elliptic curve is defined on (i.e. the number of points in the elliptic curve)
- k is the security parameter of CHARIOT and defines the length in bits of the hashed message.

The input parameters to the call function within CHARIOT are: attribute universe, attribute set, threshold policy, message, and n.
- Attribute univerise is the list of all possible attributes that may be passed in.
- Attribute set is the set of attributes that are contained on the IoT device.
- Threshold policy is a policy that contains a threshold t and a list of attributes. If the device has at least t of the specified attributes, then it is authenticated.
- message is the message which is signed digitally
- n is the upper bound on the size of the policies.
