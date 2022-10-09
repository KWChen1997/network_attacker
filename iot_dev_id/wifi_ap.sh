#!/usr/bin/env bash

# WAN="enp2s0"
# WAN="enx5ae6ba145d1e"
WAN="enp2s0"
LAN="wlp0s20f3"
IP="10.42.0.1"
MSK="255.255.255.0"

if [ "$1" == "on" ]; then
	sudo ifconfig $LAN $IP netmask $MSK

	sudo iptables -C FORWARD -i $LAN -o $WAN -j ACCEPT 2> /dev/null ||\
		sudo iptables -A FORWARD -i $LAN -o $WAN -j ACCEPT

	sudo iptables -C FORWARD -i $WAN -o $LAN -m state --state RELATED,ESTABLISHED -j ACCEPT 2> /dev/null ||\
		sudo iptables -A FORWARD -i $WAN -o $LAN -m state --state RELATED,ESTABLISHED -j ACCEPT

	sudo iptables -t nat -C POSTROUTING -o $WAN -j MASQUERADE 2> /dev/null ||\
		sudo iptables -t nat -A POSTROUTING -o $WAN -j MASQUERADE

	sudo systemctl is-active --quiet hostapd.service ||\
		sudo systemctl start hostapd.service

	sudo systemctl is-active --quiet udhcpd.service ||\
		sudo systemctl start udhcpd.service
elif [ "$1" == "off" ]; then
	! sudo iptables -C FORWARD -i $LAN -o $WAN -j ACCEPT 2> /dev/null ||\
		sudo iptables -D FORWARD -i $LAN -o $WAN -j ACCEPT

	! sudo iptables -C FORWARD -i $WAN -o $LAN -m state --state RELATED,ESTABLISHED -j ACCEPT 2> /dev/null ||\
		sudo iptables -D FORWARD -i $WAN -o $LAN -m state --state RELATED,ESTABLISHED -j ACCEPT

	! sudo iptables -t nat -C POSTROUTING -o $WAN -j MASQUERADE 2> /dev/null ||\
		sudo iptables -t nat -D POSTROUTING -o $WAN -j MASQUERADE

	! sudo systemctl is-active --quiet hostapd.service ||\
		sudo systemctl stop hostapd.service

	! sudo systemctl is-active --quiet udhcpd.service ||\
		sudo systemctl stop udhcpd.service
fi

echo "---------- Wi-Fi Interface ----------"
ifconfig $LAN

echo "---------- All Rules in iptables ----------"
sudo iptables -S

echo "---------- All Rules in NAT Table ----------"
sudo iptables -t nat -L

echo "---------- Status of hostapd ----------"
sudo systemctl status hostapd.service

echo "---------- Status of udhcpd ----------"
sudo systemctl status udhcpd.service
