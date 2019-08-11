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

  Full help message ::

	usage: main.py [-h] [-v version] [-m MSG] [-f FOPTS] [-c CMD] [-u] [-n]
				   [-r {0,1,2}]
				   type

	Tool for test on LoRaWAN server

	positional arguments:
	  type                  Data type of uplink, supported type list: ['join',
							'app', 'pull', 'cmd', 'rejoin', 'info', 'abp']

	optional arguments:
	  -h, --help            show this help message and exit
	  -v version, --version version
							Choose LoRaWAN version, 1.0.2 or 1.1(default)
	  -m MSG                FRMPayload in string
	  -f FOPTS              MAC Command in FOpts field
	  -c CMD                MAC Command in FRMPayload field
	  -u, --unconfirmed     Enable unconfirmed data up
	  -n, --new             Flag for brand new device, using device info in
							device.yml config file. Be careful this flag can
							override current device, information may be lost.
	  -r {0,1,2}, --rejoin {0,1,2}
							Specify rejoin type, default is 0
		
Tutorial
--------

- Copy a local config file and device info file(or abp.yml.tpl file for ABP mode) from the template, then modify the src and dest address.

OTAA
****

- Modify device infomation in ``device.yml`` you just copied. An example: ::

		Device:
			JoinEUI: 0000000000000000
			DevEUI: 0000000000000000
		RootKeys:
			AppKey: 00000000000000000000000000000000
			NwkKey: 00000000000000000000000000000000
		Gateway:
			GatewayEUI: 0000000000000000
    
  **Note**: If you want to emulate LoRaWAN 1.0 device, first set ``JoinEUI`` equal to ``AppEUI`` and set ``NwkKey`` equal to ``AppKey``.

ABP
***

- Modify device activation information in ``abp.yml``. An example: ::

		deveui: 91fc1bb684bf2ed6
		joineui: '0000000000000000'
		devaddr: 01c11aee
		appkey: 4c0892904bb3544138b5070c5c4069cd
		nwkkey: be60e113de86d73b52fc0005bf5d89e8
		nwksenckey: 93f7c8626b5a5d1a62f731033af9df9a
		snwksintkey: a06c9cd47db9826b103305229483467c
		fnwksintkey: 1eba330be77e3fc1546ab07c93399372
		appskey: 3bfcf2ef94bb8c5dcb08a5f0b7bf0585
		fcntup: 0 

- Install the environment, and start the virtual shell ``pipenv shell``.
- Currently, five kinds of message is supported: pull data, join request, rejoin request, confirmed (or unconfirmed) data up (with or without FOpts) and MAC Commands in FRMPayload field:

::  

	python main.py info
	python main.py abp
	python main.py pull
	python main.py join
	python main.py rejoin -r (your type of rejoin)
	python main.py app -m (your uplink message, will be encoded by UTF-8) -f (your MACCommand in FOpts field) -n (brand new device)
	python main.py mac -c (your MAC Command in FRMPayload field)

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
