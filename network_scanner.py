import re, sys
import scapy.all as scapy
from termcolor import colored
from optparse import OptionParser


def print_result(clients_list: list):
    """
        Output table result devices in the network
    """
    try:
        print('============================================================')
        print(f"\t{colored('IP-address', 'yellow', attrs=['bold'])}\t|\t{colored('MAC-address', 'yellow', attrs=['bold'])}")
        print('============================================================')
        for idx, client in enumerate(clients_list):
            print(f"\t{colored(client['ip'], 'cyan', attrs=['bold'])}\t|\t{colored(client['mac'], 'cyan', attrs=['bold'])}")
            print('============================================================')
        print(f"{colored('Total devices in the network', 'blue')} : {len(clients_list)}\n", attrs=['bold'])
    except Exception:
        print(colored('[-] An error occurred while show result', 'red', attrs=['bold']))


def arg_func():
    """
        Arguments from command string
    """
    try:
        parser = OptionParser()
        parser.add_option("-i", "--ip", dest="ip", help="Enter your IP start address network")
        options, _ = parser.parse_args()
        # Check enter all arguments
        if not options.ip:
            parser.error(colored("Enter IP-address network -i or --ip", "yellow", attrs=['bold']))
            sys.exit()
        else:
            return options.ip
    except Exception:
        print(colored('[-] An error occurred while adding arguments', 'red', attrs=['bold']))


def scan(ip: str):
    """
        ARP Request for get MAC-addresses devices in the network
    """
    try:
        answered_list, unanswered_list = scapy.srp(
            scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip), timeout=10, verbose=False
        )

        clients_list = []
        for answered in answered_list:
            client_dict = {"ip": answered[1].psrc, "mac": answered[1].hwsrc}
            clients_list.append(client_dict)

        print_result(clients_list)
    except Exception:
        print(colored('[-] An error occurred while scan network', 'red', attrs=['bold']))


ip = arg_func()
scan(f"{ip}/24")
