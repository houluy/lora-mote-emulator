LoRa Motes Emulator
===================

This is a useful tool to test LoRa server.

To emulate end devices (AKA Motes in |LoRaWAN(TM)| protocol)

*Support* |LoRaWAN(TM)| *1.0.2 protocol*

**Using Gateways from** |Semtech(TM)|

.. |LoRaWAN(TM)| unicode:: LoRaWAN U+2122
.. |Semtech(TM)| unicode:: Semtech U+2122


System Requirements
======================

- Python(3.6, mandatory)

Installtion
===================

- Use ``pip`` to install ``pipenv``::

  (sudo) pip3 install pipenv

- Clone this repo into a directory::

  git clone https://github.com/houluy/lora-motes-emulator.git

- Use ``pipenv`` to create a virtual Python environment and install all the dependencies::

  pipenv --python 3 install
  
Here, if there is not Python 3.6 in your system, it is perfect to install one from `source <https://www.python.org/downloads/release/python-362/>`_
