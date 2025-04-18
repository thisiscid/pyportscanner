import sys
from scapy.all import IP, sr1, TCP, ICMP, UDP
import signal
import argparse
import string

class PortParseError(Exception):
    """Error raised when ports_parser reports that the supplied ports are invalid"""
    pass
def main():
    parser = argparse.ArgumentParser(description="A simple TCP port scanner built in Python")
    parser.add_argument("target", help="IP address or hostname to scan")
    parser.add_argument("--ports", help="Port range (e.g. 1-1000). Ports should be seperated via comma (eg. 1,2,3,4).", default="1-1024")
    parser.add_argument("--no-ping", action="store_true", help="Skip host ping check (useful if ICMP is blocked)")
    parser.add_argument("--output", help="Save results to a file")  
    args = parser.parse_args()
    DESTINATION = args.target
    try:
        PORTS = ports_parser(args.ports)
    except PortParseError as error_msg:
        parser.error(str(error_msg))
    PING_TRUE_OR_FALSE = args.no_ping
    OUTPUT = args.output
    try:
        print(f"Now scanning {DESTINATION} in ports {PORTS[0]} to {PORTS[-1]}")
        syn_scan(PING_TRUE_OR_FALSE, DESTINATION, PORTS)
    except PermissionError:
        print("Lacking root privileges for scan. Are you using sudo?")
        sys.exit(1)

def handle_interrupt(signum, frame):
    print("\n[!] Keyboard interrupt detected — exiting.")
    sys.exit(0)
signal.signal(signal.SIGINT, handle_interrupt)

def ports_parser(ports):
    ports_list=ports.split(",")
    ports_return=[]
    for port in ports_list:
        if any(char.isalpha() for char in port):
            raise PortParseError("Cannot parse ports — letters detected. Did you use letters on accident?")
        elif "-" not in port:
            ports_return.append(int(port))
        elif "-" in port:
            temp=port.split("-")
            sorted_port=[]
            if len(temp)>2:
                raise PortParseError("Cannot parse ports — invalid range detected. Did you write your range right?")
            for number in temp:
                sorted_port.append(int(number))
            sorted_port.sort()
            sorted_port.extend(range(sorted_port[0],sorted_port[1]+1))
            ports_return.extend(sorted_port)
    ports_return = sorted(set(ports_return))
    return ports_return
                

def ping_dest(destination):
    """Pings the destination using ICMP, TCP, and UDP (in that order in the event that TCP or UDP fails)
    param: str - target to ping
    output: bool - is destination up or not
    """
    ans= sr1(IP(dst=destination)/ICMP(), timeout=3); print("Trying ICMP Ping...")
    if ans is None:
        ans = sr1( IP(dst=destination)/TCP(dport=80,flags="S") ); print("ICMP Ping failed, trying TCP Ping...")
        if ans is None:
            ans = sr1( IP(dst=destination)/UDP(dport=0) ); print("TCP Ping failed, trying UDP ping...")
            if ans is None:
                return False
            return True
        return True
    return True

def syn_scan(skip_ping,destination,ports=range(1,1025)):
    """Takes in a list ports to scan, with default being 1-1024, and a destination that it scans.
    param: list - ports to scan
    output: str - whether a port is up or not
    """
    if not skip_ping:
        if not ping_dest(destination):
            raise ConnectionRefusedError("Could not ping host. Are you sure that the host is up?")
    for port in ports:
        try:
            packet = IP(dst=destination)/TCP(dport=port, flags="S")  # SYN
            response = sr1(packet, timeout=1, verbose=False)
            if response is None:
                print(f"Response empty. Port {port} is filtered (No response received)")
                continue
            if response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                    print(f"Port {port} is open (SYN-ACK received)")
                elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
                    print(f"Port {port} is closed (RST received)")
        except KeyboardInterrupt:
            print("Keyboard interrupt, exiting...")
            sys.exit(0)

if __name__ == "__main__":
    main()