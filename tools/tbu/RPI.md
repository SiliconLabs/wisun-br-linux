# Setting up a Raspberry Pi

This file gives instructions to prepare a device as a Wi-SUN LBR TBU using a
Rapsberry Pi 2, an adapter board (BRD8016A), and a radio board (BRD4271A).
This is mostly a collection of commands gathered while setupping a device.
Users are expected to login using SSH as user `pi` and read
`/home/pi/README.txt`.

## Preliminary steps

- Install Raspbian on an SD card with user `pi` using `rpi-imager`, don't forget
  to enable SSH.
- Flash a bootloader on the radio board.
- Flass an RCP app on the radio board.
- Set the interposer switch on high power (LDO).

## RCP firmware updates

In case a firmware update is needed for the RCP, a GBL file should be provided
in `/home/pi/wisun_rcp.gbl` so that users simply need to run the following
command:

    wsbrd-fwup -u /dev/ttyAMA0 /home/pi/fw/wisun_rcp.gbl

## System preparation

    sudo apt-get install              \
        cmake ninja-build pkg-config  \
        libnl-3-dev libnl-route-3-dev \
        libcap-dev libsystemd-dev     \
        lrzsz vim
    rm -r                  \
        /home/pi/Bookshelf \
        /home/pi/Desktop   \
        /home/pi/Downloads \
        /home/pi/Documents \
        /home/pi/Music     \
        /home/pi/Pictures  \
        /home/pi/Public    \
        /home/pi/Templates \
        /home/pi/Videos
    mkdir /home/pi/src

## `MbedTLS`

    git clone                              \
        --branch=v3.0.0                    \
        https://github.com/ARMmbed/mbedtls \
        /home/pi/src/mbedtls
    cmake                             \
        -S /home/pi/src/mbedtls       \
        -B /home/pi/src/mbedtls/build \
        -D ENABLE_TESTING=OFF         \
        -D ENABLE_PROGRAMS=OFF        \
        -G Ninja
    ninja -C /home/pi/src/mbedtls/build -j $(nproc)
    sudo ninja -C /home/pi/src/mbedtls/build install

## `wsbrd`

    git clone                                             \
        --branch=v1.7                                     \
        https://github.com/SiliconLabs/wisun-br-linux.git \
        /home/pi/src/wisun-br-linux
    cmake                                    \
        -S /home/pi/src/wisun-br-linux       \
        -B /home/pi/src/wisun-br-linux/build \
        -G Ninja
    ninja -C /home/pi/src/wisun-br-linux/build -j $(nproc)
    sudo ninja -C /home/pi/src/wisun-br-linux/build install

## `Dnsmasq`

    git clone                               \
        --branch=v2.89                      \
        git://thekelleys.org.uk/dnsmasq.git \
        /home/pi/src/dnsmasq
    make -C /home/pi/src/dnsmasq -j $(nproc)
    sudo make -C /home/pi/src/dnsmasq install

## TBU server

    sudo pip3 install -r /home/pi/src/wisun-br-linux/tbu/requirements.txt
    sudo install -m 0644 /home/pi/src/wisun-br-linux/tools/tbu/systemd/wisun-borderrouter.service /etc/systemd/system
    sudo install -m 0644 /home/pi/src/wisun-br-linux/tools/tbu/systemd/wstbu-dhcpv6-relay.service /usr/local/lib/systemd/system
    sudo install -m 0755 /home/pi/src/wisun-br-linux/tools/tbu/systemd/wstbu-dhcpv6-relay         /usr/local/bin

To setup a service for the TBU server:

    sudo install -m 0644 /home/pi/src/wisun-br-linux/tools/tbu/config.ini /etc/wstbu-server.ini
    sudo sed -i 's/ttyACM0/ttyAMA0/g' /etc/wstbu-server.ini
    sudo tee -a /usr/local/lib/systemd/system/wstbu-server.service <<- EOF
    	[Service]
    	WorkingDirectory=/home/pi/src/wisun-br-linux/tools/tbu
    	ExecStart=python3 /home/pi/src/wisun-br-linux/tools/tbu/wstbu.py /etc/wstbu-server.ini
    EOF

Don't forget to refresh the services:

    sudo systemctl daemon-reload

## `README.txt`

    cat <<- EOF > /home/pi/README.txt
    	To configure the TBU server, edit /etc/wstbu-server.ini.

    	To run the TBU server start the service wstbu-server:

    	    sudo systemctl start wstbu-server.service

    	To check logs for the TBU server, or for the border router, use journalctl:

    	    sudo journalctl -u wstbu-server.service
    	    sudo journalctl -u wisun-borderrouter.service

    	To update the RCP firmware:

    	    sudo wsbrd-fwup -u /dev/ttyAMA0 /home/pi/fw/wisun_rcp.gbl

    EOF

## Device tree configuration for the expansion board

These steps are described in more detail in [AN1332][1].

[1]: https://www.silabs.com/documents/public/application-notes/an1332-wi-sun-network-configuration.pdf

    sudo tee -a /boot/config.txt <<- EOF
    	[all]
    	dtoverlay=disable-bt
    	enable_uart=1
        # Trigger the reset pin
        gpio=23=op,dh
    EOF
    sudo reboot
    sudo raspi-config nonint do_serial 2
    sudo reboot
