#!/bin/bash

INSTALL_DIR=/home/$USER/Tools/AdaptixC2

if [ -d $INSTALL_DIR ]; then
    echo "[-] Removing current installation"
    sudo rm -rf $INSTALL_DIR && echo "[+] Done!"
fi

echo "[+] Cloning AdaptixC2: Main"
git clone "https://github.com/Adaptix-Framework/AdaptixC2" $INSTALL_DIR

echo "[+] Cloning AdaptixC2: Extension-Kit"
git clone "https://github.com/Adaptix-Framework/Extension-Kit" $INSTALL_DIR/Extension-Kit

echo "[+] Installing/Updating Prerequisites"
chmod +x $INSTALL_DIR/pre_install_linux_all.sh
sh $INSTALL_DIR/pre_install_linux_all.sh

echo "[+] Building Server, Extenders, Client, Extensions"
cd $INSTALL_DIR
make server
make extenders
make client
cd $INSTALL_DIR/Extension-Kit/
make

echo "[+] Generating SSL certs"
chmod +x $INSTALL_DIR/dist/ssl_gen.sh
echo -e "\n\n\n\n\n\n\n\n\n" | sh $INSTALL_DIR/dist/ssl_gen.sh

echo "[+] Done. Enjoy!"
