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

- Ubuntu
- Python(3.6, mandatory)

Installtion
===================

- Use ``pip`` to install ``pipenv``::

  (sudo) pip3 install pipenv

- Clone this repo into a directory::

    git clone https://github.com/houluy/lora-motes-emulator.git

- Use ``pipenv`` to create a virtual Python environment and install all the dependencies::

    pipenv --python 3 install
  
Here, if there is not Python 3.6 in your system, a warning will occur, and no package will be installed. It is perfect to install Python 3.6 from `source <https://www.python.org/downloads/release/python-362/>`_. Otherwise, remove the ``Pipfile.lock`` and redo the above command.

- Copy a local config file and modify the src and dest address.
- Modify device basic infomation in ``device_back.json``.
- Run the emulator to see the help::

    pipenv run python main.py -h

  or by::

    pipenv shell
    python main.py -h
