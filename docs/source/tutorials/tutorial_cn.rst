============
使用教程
============

-----------
简介
-----------
本程序基于Python语言开发，能够模拟LoRa终端及网关收发LoRaWAN数据包的功能，用于LoRa服务器的正确性测试。

-----------
安装
-----------
本程序支持Python 3.6+版本，跨平台。建议采用 ``pipenv`` 管理依赖环境。

1. 确保机器中已安装Python > 3.6，且pip已升级至最新版本。（升级pip：``pip install --upgrade pip``）

2. 建议安装 ``pipenv``：

::

    pip install pipenv

3. 在一个空目录下创建新的虚拟环境：

::

    pipenv --python 3

4. 修改 ``Pipfile`` 文件，将 ``pypi`` 源改为国内镜像以提高访问速度，例如，清华源 ``https://pypi.tuna.tsinghua.edu.cn/simple``。

5. 安装本程序：

::

    pipenv install lora-mote-emulator

至此，本程序已正确安装至虚拟环境中。

------------
使用方法
------------

本程序包含一个可执行脚本 ``mote`` ，可以通过 ``mote -h`` 查看完整帮助信息

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

+++++++++++++
网关准备
+++++++++++++

1. 在初次使用程序时，需要运行 ``mote create [-c config_dir]`` 来创建默认配置文件，
包括 ``device.json`` , ``gateway.json``, ``config.json``, ``abp.json``。 ``-c`` 为可选参数，
用于指定配置文件生成的目录，默认为 ``./config`` 。

2. 修改配置文件的内容，其中：

    -  ``config.json`` 中包含目标服务器的IP地址及端口号，日志层级，超时时间等；
    -  ``gateway.json`` 中包含网关的标识符（Extended Unique Identifier, EUI）；
    -  ``device.json`` 中包含终端的详细信息，包括 ``DevEUI`` , ``JoinEUI`` 以及两个根密钥 ``AppKey`` , ``NwkKey`` ;
    -  ``abp.json`` 如果终端采用个性化激活（Activation by Personalization, ABP）模式入网，则需要修改本配置文件，其中包括设备激活所需的所有字段信息，例如各种会话密钥、终端网络地址等；

3. 在开始发送终端消息前，必须先通过网关的 ``PULL_DATA`` 注册网关的IP地址到服务器（ **重要** ： 部分LoRaWAN服务的实现要求网关定期发送 ``PULL_DATA`` 保持连通性，因此，当无法收到下行数据时，可以尝试 **重新发送** ``PULL_DATA`` 消息）。 ``PULL_DATA`` 发送命令如下：

::

    mote pull

4. 当产生如下日志时，表明收到了服务器返回的 ``PULL_ACK`` 消息，后续可以进行终端的相关操作。

++++++++++++++
终端命令
++++++++++++++

本程序支持的LoRaWAN上行消息包括：

- *Join Request* ,

- *Confirmed Uplink* ,

- *Unconfirmed Uplink* ,

- *Rejoin Request* ,

- *MACCommand* ,

下行消息包括：

- *Join Accept* ,

- *Confirmed Downlink* ,

- *Unconfirmed Downlink* 。

%%%%%%%%%%%%%%%
激活
%%%%%%%%%%%%%%%

首先，终端需要入网后才能继续使用，入网有两种模式，即**空口入网（Over-the-air Activation, OTAA）** 和**ABP**模式。

**************
OTAA
**************

OTAA是指终端和服务器以协商的方式完成入网，建立会话，并生成各类会话密钥。其过程如下：

1. 首先需要在LoRaWAN服务器上注册应用及终端EUI，以及两个根密钥；
2. 修改 ``device.json`` 文件对应字段；
3. 运行 ``mote pull`` ；
4. 运行 ``mote join -n`` ，其中可选参数 ``-n`` 表示建立全新的会话，覆盖以前的终端；
5. 当返回日志中显示 ``INFO - Join Accept (MIC verified)`` 表示收到了 *Join Accept* 消息且经过了消息完整性码（Message Integrity Code, MIC）校验。此时终端入网成功，可以正常发送上行应用数据。

**************
ABP
**************

ABP是指直接在服务器和终端侧将会话字段预设，然后直接进行通信对方式。其过程如下：

1. 首先需要在LoRaWAN服务器上设置终端激活模式为ABP，并设置好会话字段；
2. 修改 ``abp.json`` 配置文件各个对应字段；
3. 运行 ``mote abp`` ，将打印出终端信息，表示已设置成功，可以进行应用数据发送；

%%%%%%%%%%%%%%%
上下行应用数据
%%%%%%%%%%%%%%%

终端激活成功后，可以实现上下行数据发送接收。下行数据只能在发送 **上行数据之后** 才能接收到。上行应用数据命令如下：

::

    mote app [-au] [-f fopts] [msg]

其中，可选参数 ``-a`` 表示将上行数据的 **ACK** 比特位置位， ``-u`` 表示发送 *Unconfirmed Uplink* ， ``-f fopts`` 表示应用数据中包含 *FOpts* （MACCommands）， ``msg`` 为实际需要发送的字符串，将由 ``UTF-8`` 编码，例如：

::

    mote app -au -f 01 hello_world

表示发送 *Unconfirmed Uplink* 消息， **ACK** 比特位置位，包含 *FOpts*  ``0x01`` ，应用消息为字符串 ``hello_world`` 。

根据不同的LoRaWAN服务器实现，终端可能收到不同的下行消息，也可能收不到回复（ *Unconfirmed Uplink* ）。本程序将等待一定时间（ ``config.json`` 中 ``timeout`` 字段）后超时停止。

当收到下行消息时，命令行将显示 ``INFO - Downlink MACPayload (MIC verified)``，并显示该消息中的关键字段。

%%%%%%%%%%%%%%%%%
重新入网请求
%%%%%%%%%%%%%%%%%

本程序支持发送三类 *Rejoin Request* 请求（LoRaWAN Version 1.1.0新增），请求格式如下：

::

    mote rejoin {0,1,2}

服务器若同意请求，则返回 *Join Accept* 消息。

%%%%%%%%%%%%%%%%%
MACCommand
%%%%%%%%%%%%%%%%%

本程序支持通过 *FRMPayload* 发送 *MACCommand* 命令，即 *FPorts = 0* ，请求格式如下：

::

    mote mac [-au] [cmd]

其中，可选参数 ``-au`` 作用和应用消息一致； ``[cmd]`` 表示实际发送的MACCommand指令的十六进制字符串形式。例如，发送 ``0x01`` ，则采用如下命令：

::

    mote mac 01

%%%%%%%%%%%%%%%%%
查看终端信息
%%%%%%%%%%%%%%%%%

查看终端信息采用 ``mote info`` 即可。

