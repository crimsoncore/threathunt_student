#!/bin/sh

# Install Sigma
python3 -m pip install sigmatools==0.18.0
pip3 show sigmatools

cd /opt
sudo git clone https://github.com/crimsoncore/sigma.git

sigmac -l