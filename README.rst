LoRa Motes Emulator
===================

|version|
|python| 
|license|

This is a useful tool to test LoRa server.

To emulate end devices (a.k.a. Motes in |LoRaWAN(TM)| protocol)

*Support* |LoRaWAN(TM)| *1.0.2 & 1.1 protocol*

**Using Gateways from** |Semtech(TM)|

.. |LoRaWAN(TM)| unicode:: LoRaWAN U+2122
.. |Semtech(TM)| unicode:: Semtech U+2122


System Requirements
-------------------

- Ubuntu
- Python(>=3.6, mandatory)

Installtion
-------------------

- Use ``pip`` to install ``pipenv``::

  (sudo) pip3 install pipenv

- Clone this repo into a directory::

    git clone https://github.com/houluy/lora-motes-emulator.git

- Use ``pipenv`` to create a virtual Python environment and install all the dependencies::

    pipenv --python 3 install
  
Here, if there is not Python 3.6 in your system, a warning will occur, and no package will be installed. It is perfect to install Python 3.6 from `source <https://www.python.org/downloads/release/python-362/>`_. Otherwise, remove the ``Pipfile.lock`` and redo the above command.

- Run the emulator to see the help::

    pipenv run python main.py -h

  or by::

    pipenv shell
    python main.py -h

  Full help message::
	usage: main.py [-h] [-n version] [-m MSG] [-f FOPTS] [-c CMD] [-d] [-u]
				   [-r {0,1,2}]
				   type

	Tool for test on LoRaWAN server

	positional arguments:
	  type                  Data type of uplink, supported type list: ['join',
							'app', 'pull', 'cmd', 'rejoin']

	optional arguments:
	  -h, --help            show this help message and exit
	  -n version, --version version
							Choose LoRaWAN version, 1.0.2 or 1.1(default)
	  -m MSG                Payload
	  -f FOPTS              MAC Command in FOpts field
	  -c CMD                MAC Command in FRMPayload field
	  -d, --debug           Start debug mode, log more infomation
	  -u, --unconfirmed     Enable unconfirmed data up
	  -r {0,1,2}, --rejoin {0,1,2}
							Specify rejoin type, default is 0

Tutorial
--------

- Copy a local config file and device info file from the template, then modify the src and dest address.
- Modify device infomation in ``device.json`` you just copied. An example: ::

        {
          "Device": {
            "JoinEUI": "0000000000000000",
            "DevEUI": "0000000000000000"
          },
          "keys": {
            "AppKey": "00000000000000000000000000000000",
            "NwkKey": "00000000000000000000000000000000"
          },
          "Gateway": {
            "GatewayEUI": "0000000000000000"
          }
        }
    
  **Note**: If you want to emulate LoRaWAN 1.0 device, first set ``JoinEUI`` equal to ``AppEUI`` and set ``NwkKey`` equal to ``AppKey``, then, add ``-n 1.0.2`` flag when sending app data.

- Install the environment, and start the virtual shell ``pipenv shell``.
- Currently, four kinds of message is supported: pull data, join request, confirmed (or unconfirmed) data up (with or without FOpts) and MAC Commands in FRMPayload field:

::  

    python main.py pull
    python main.py join
    python main.py app -m (your uplink message, will be encoded by UTF-8) -f (your MACCommand in FOpts field)
    python main.py mac -c (your MAC Command in FRMPayload field)

If this is your first-time running, delete ``device.pkl`` file in ``models`` directory at first, then, run ``pull`` and ``join`` to register the port of gateway and join the device. The device info will be saved automatically in ``models/device.pkl`` using ``pickle``, and loaded next time.

Here is the example of normal message:

::  

    python main.py app -m helloworld -f 0302
    python main.py mac -c 0302

Contribution
------------

This repo is hosted on https://github.com/houluy/lora-motes-emulator and under MIT license, any contribution or suggestion is welcome. Just open an issue or send a pull request.


.. |version| image:: https://img.shields.io/badge/LoRaWAN-1.1-orange.svg?style=plastic
.. |python| image:: https://img.shields.io/badge/Python-3.6%2C3.7-blue.svg?style=plastic&logo=python
.. |license| image:: https://img.shields.io/badge/License-MIT-red.svg?style=plastic
