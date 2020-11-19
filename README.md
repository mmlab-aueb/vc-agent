#  VC-agent
A python3 partial implementation of W3C Verifiable Credentials standard

# Installation
This script has the following prerequisites:
* pip3 install jwcrypto 
* pip3 install PyLD
* pip3 install jsonpath-ng

# Using
The script can be used for singing and verifying credentials.
See `examples.py` for a complete example. 


# Testing 
Test are implemented using pytest. You can install it using
* pip3 install pytest

Tests are executed by invoking
* python3 -m pytest -s tests/

For smaller outputs append the above command with `--tb=short'