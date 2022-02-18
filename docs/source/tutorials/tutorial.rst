============
Tutorials
============

------------
Introduction
------------

``lora-mote-emulator`` is developed by Python. It can emulate LoRa motes (a.k.a end-devices) and LoRa Gateways to send and receive LoRaWAN packages.
It can be mainly utilized to test LoRaWAN servers.

------------
Installation
------------

``lora-mote-emulator`` supports Python 3.6+, and is distributed via Pypi. Therefore, we can directly use ``pip`` to install
this program. Meanwhile, ``pipenv`` is recommended to manage virtual environments.

1. Make sure Python > 3.6 is installed on the machine, and ``pip`` is upgraded to the latest version. To upgrade ``pip``, use
``pip install --upgrade pip`` .

2. Install ``pipenv``:

::

    pip install pipenv

3. Create a new virtual environment in an empty directory:

::

    pipenv --python 3

4. Install ``lora-mote-emulator``:

::

    pipenv install lora-mote-emulator

Now, the emulator is installed successfully.

------------
Usage
------------

The emulator includes an executable ``mote``, thus, ``mote -h`` can show the help message

::

    usage: mote [-h] [-v version] [-c CONFIG] [--model MODEL]
        {join,app,pull,mac,rejoin,info,abp,create} ...

    Tool to emulate LoRa mote (a.k.a end-device) and Gateway, supported command
    list: ['join', 'app', 'pull', 'mac', 'rejoin', 'info', 'abp', 'create']

    optional arguments:
        -h, --help              show this help message and exit
        -v version, --version version
                                Choose LoRaWAN version, 1.0.2 or 1.1(default)
        -c CONFIG, --config CONFIG
                                Specify the directory of config files, default './config'
        --model MODEL         Specify the directory to save the model file, default './models'

    Supported commands:
        {join,app,pull,mac,rejoin,info,abp,create}
        join                Send join request.
        app                 Send application data.
        pull                Send PULL_DATA.
        mac                 Send MACCommand.
        rejoin              Send rejoin request.
        info                Show information of current mote.
        abp                 Initialize mote in ABP mode.
        create              Handle configurations.

+++++++++++++++
Prepare gateway
+++++++++++++++

1. At the very beginning, we need to create configuration files. Run ``mote create [-c config_dir]`` to generate configuration
files at directory ``config_dir`` ( ``./config`` in default). The configuration files include ``device.json``, ``gateway.json``,
``config.json``, and ``abp.json``.

2. Modify the content of each configuration file:

- ``config.json`` includes the server's IP address and port number, log level and timeout, etc.
- ``gateway.json`` includes the gateway's extended unique identifier (EUI),
- ``device.json`` includes the detailed parameters of mote, i.e., ``DevEUI``, ``JoinEUI`` and two root keys, i.e., ``AppKey`` and ``NwkKey``,
- ``abp.json`` includes required fields if mote is activated via Activation by Personalization (ABP) mode.

3. Before mote sending message, the gateway needs to register the IP address to server via ``PULL_DATA`` message.
( **Note**: Some LoRaWAN servers may require gateways to send ``PULL_DATA`` periodically to keep-alive. Therefore, if we
get nothing from servers, we can send a ``PULL_DATA`` first, then re-try the message. To send a ``PULL_DATA`` message,
use following command:

::

    mote pull

4. If ``INFO - PULL ACK -`` logs, it means a ``PULL_ACK`` message is received from server. Since then, mote can send real
LoRaWAN messages.

++++++++++++++
Mote commands
++++++++++++++

All the supported LoRaWAN uplink message types are as follows:

- *Join Request* ,

- *Confirmed Uplink* ,

- *Unconfirmed Uplink* ,

- *Rejoin Request* ,

- *MACCommand* ,

Downlink message types include：

- *Join Accept* ,

- *Confirmed Downlink* ,

- *Unconfirmed Downlink* 。

%%%%%%%%%%%%%%%
Activation
%%%%%%%%%%%%%%%

First of all, the mote needs to be activated before using. There are two modes of activations, i.e., Over-the-air Activation (OTAA),
and ABP.

**************
OTAA
**************

OTAA stands for the activation by which mote need to negotiate with server to establish session and generate various
session keys. To activate mote in OTAA mode, do the following:

1. Register application and mote EUI (JoinEUI and DevEUI), and the two root keys,
2. Modify ``device.json`` config file,
3. Run ``mote pull`` ,
4. Run ``mote join -n`` , where ``-n`` option means to establish brand new session which may override the old one.
5. When the log shows  ``INFO - Join Accept (MIC verified)`` , it means that a *Join Accept* message is received and the message integrity code (MIC) is verified. Now the mote has been activated, and can be used to send application messages.

**************
ABP
**************

ABP mode means that the session parameters are preset in both server and mote sides, making them able to communicate directly.
The process is shown as follows:

1. Set the activation mode to be ABP on LoRaWAN server, and set all the session parameters,
2. Modify ``abp.json`` file on all fields,
3. Run ``mote abp``. If the mote information is printed, the ABP activation succeeds.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
Uplink & Downlink Application message
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

After activation, the mode can send and receive application data. Downlink message can **only** be received after sending
an uplink message successfully. To send uplink message, use:

::

    mote app [-au] [-f fopts] [msg]

where ``-a`` option means to set the **ACK** flag in uplink package, ``-u`` option stands for *Unconfirmed Uplink* message type,
and ``-f fopts`` means the package include *FOpts* (MACCommands). ``msg`` is the actual string that needs to be sent, and
it will be encoded by ``UTF-8``. For example:

::

    mote app -au -f 01 hello_world

means send an *Unconfirmed Uplink* message, set the **ACK** flag, and include *FOpts*  ``0x01`` . The application message
is the string ``hello_world`` .

According to different implementation of LoRaWAN server, the downlink messages could be quite different. There may also
be no reply ( *Unconfirmed Uplink* ). ``lora-mote-emulator`` will wait until timeout.

When a downlink message is received, the command line will display message ``INFO - Downlink MACPayload (MIC verified)``,
and show some important fields.

%%%%%%%%%%%%%%%%%
Rejoin request
%%%%%%%%%%%%%%%%%

Our program supports to send all three types of *Rejoin Request* (New in LoRaWAN Version 1.1.0), e.g.:

::

    mote rejoin {0,1,2}

If server agrees the request, it will reply with *Join Accept* message.

%%%%%%%%%%%%%%%%%
MACCommand
%%%%%%%%%%%%%%%%%

``mote`` can send *MACCommand* via *FRMPayload* field, i.e. *FPorts = 0*. The command is as follow:

::

    mote mac [-au] [cmd]

where ``-au`` act the same as in ``app`` , and ``[cmd]`` stands for the actual commands (in hex string form) that needs
to be sent. For example, to send ``0x01`` , use:

::

    mote mac 01

%%%%%%%%%%%%%%%%%%%%%%
Check mote information
%%%%%%%%%%%%%%%%%%%%%%

Use ``mote info`` to display the information of current mote.

