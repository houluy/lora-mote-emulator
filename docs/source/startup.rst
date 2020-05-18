ChirpStack
==========

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
    - Fill in a Device EUI,
    - Choose a device profile,
    - Optional: uncheck the frame-counter validation for convenient test.
12. After click the CREATE DEVICE button, ``NwkKey`` and ``AppKey`` need to be filled (For LoRaWAN 1.0.2, only ``AppKey`` is needed), then the configuration of ChirpStack server is completed.
13. Now, we can use lora-motes-emulator to issue join request in OTAA mode.
    - Modify the config files.
    - 
