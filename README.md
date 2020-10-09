# Arch-tracert

Arch-tracert is a simple tracert with a little more functionality, that I wanted to create and practice my networking knowledge and python abilities with.
This project uses the Scapy module (so make sure it's installed if something doesn't work).
The name consists of "arch" and "tracert". While the second one is pretty obvious, "arch" stands for "elite", meaning this tracert will be much more cooler than the regular tracert... I hope :D.

## Features

1. tracert based on icmp.
2. tracert based on TCP.
3. tracert based on UDP.
4. save the log of the tracert as txt file in the current folder.
5. save html page with the geographic map of the tracert route.

---

## Installation

Clone or download this repository and run the script.

## Usage

Run it in a shell with the appropriate parameters (if you are not sure, use -h flag for help and more options).

### recuired arguments

```
-a  --address   The targets IP address.
```

### optional arguments

```
-i  --icmp      ICMP traceroute (by default).
-u  --udp       UDP traceroute.
-t  --tcp       TCP traceroute.
-l  --log       Save the results log in a txt file.
-d, --detail    Print more details about each ip in the tracert result.
-m  --map       Maps the ip addresses by their geographical location.
```

## Example

For example, if you want to run tracert based on UDP to the ip address 4.2.0.69, and save the log and a geographic map, you should run this:

```
python arch_tracert.py -a 4.2.0.69 -u -l -m
```
