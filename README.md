# Man in the Middle attacks - The dangers of using HTTP instead of HTTPS in an open network

This project is the final assignment for the **Computer Networks** class of Information Systems degree in _Universidade Federal Fluminense (UFF)_.

The purpose of it is to show the importance of always using safe protocols like HTTPS instead of unreliable/old ones like HTTP.

For this, I'll simulate an _Man in the Middle_ attack inside a private network using the **ARP Spoofing** method. This method consists in an attacker sending ARP messages to a local network, aiming to associate the attacker's _MAC address_ with the _IP adress_ of another host. After the _spoofing_ is made, the attacker starts a _sniffer_ to get all communications made between the intercepted host and the local network.

Each _sniffer_ used in this project intercepts a kind of protocol. One for HTTP and the other for HTTPS. The purpose is to compare the data stolen from the HTTP, which is completly readable, and the data stolen from the HTTPS, which we can not read, since it's encrypted.

## Usage

- **TODO**

## Conclusion

- **TODO**
