Use ChirpStack as LoRa Server
=============================

Please refer to the official website for more information. https://www.chirpstack.io/guides/docker-compose/

1. Install ``docker``.  

2. Clone the repo ``https://github.com/brocaar/chirpstack-docker.git``.

3. ``docker-compose up``.

4. Open a browser, visit the default application server ``https://localhost:8080``.

5. Login with default username and password, both are ``admin``.

6. Setup a network-server. The default is ``chirpstack-network-server:8000``.

7. Create ``Service-profiles``.

8. Create ``Device-profiles``.

9. Register a gateway, and fill in a Gateway EUI.

10. Create an application, select a service profile.

11. Click the application name, and create a device belongs to the application.
    * Fill in a Device EUI,
    * Choose a device profile,
    * Optional: uncheck the frame-counter validation for convenient test.

12. After click the CREATE DEVICE button, ``NwkKey`` and ``AppKey`` need to be filled (For **LoRaWAN 1.0.2**, only ``AppKey`` is needed), then the configuration of ChirpStack server is completed.

13. Now, we can use lora-motes-emulator to issue join request in OTAA mode. (This part is also shown in README.rst)
    * Prepare the config files.
      # For **LoRaWAN 1.0.2**, copy the template file ``config/device102.yml.tpl`` as ``config/device.yml``, for **LoRaWAN 1.1**, copy the template file ``config/device.yml.tpl`` as ``config/device.yml``. 
      # Modify the ``device.yml`` file and fill in the information according to the register information at step 8.
      # Copy the ``config/config.yml.tpl`` as ``config/config.yml``, fill in the IP and port information of ChirpStack server (Default port number is 1700).
    * Start the ``pipenv`` environment by ``pipenv shell``.
    * Send a **PULL_DATA** to ChirpStack server by ``python main.py pull``.
    * Send a **join request message** to ChirpStack server by ``python main.py join``.
    * If the **join accept message** is decoded successfully, we can check the device information by ``python main.py info``.
    * An **Uplink message** can be sent by ``python main.py app -m YOUR_MESSAGE``, which can also combine with MAC command by option ``-f MAC_COMMAND_ID``.

14. Key Points:
    * The **Uplink data rate index** and the **Channel index** is required to calculate the MIC field (B1 message) in version 1.1.
