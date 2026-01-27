echo "connecting to hkcert team 11 in the background"

sudo openvpn --config hkcertctf-team11.ovpn --tun-mtu-max 64800 --daemon
ip route show dev tun0
