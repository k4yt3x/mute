# MUTE PROJECT                                     

DISCLAIMER: This application is NOT for educational purposes.
Abusing this program might be an illegal action.
Use this program ON YOUR OWN RISK. The authors of this program
won't be responsible to any results caused by abusing this program.

YOU'RE EXPECTED TO KNOW WHAT YOU'RE DOING

Description: MUTE (WxKill) is an Python Application that kills wifi signals

REQUIRED PACKAGES:
## Aircrack-NG suite (aireplay-ng; airmon-ng; airodump-ng) 

Install in one command (Debian/ Ubuntu):
~~~~
# apt install aircrack-ng
~~~~

If there's an error, add the following line to /etc/apt/sources.list:
~~~~
deb http://http.kali.org/kali kali-rolling main contrib non-free
~~~~

Then type
~~~~
# apt update && apt install aircrack-ng
~~~~

# MUTE USAGE:

1. Python3 /path/too/file/mute.py
2. Select the interface you want to use
3. MUTE program will then call airmon-ng to enable monitor mode and airodump-ng to 
    start listening to wifi signals
4. Press Ctrl+C when you see the target wifi appears on the screen
5. Type the target SSID in and press Enter
6. Then MUTE program will call aireplay-ng to start attacking the target wifi
7. Press Ctrl+C when you want to stop the attack
8. MUTE program disables monitor mode on adapter and exit


# MORE USAGES:
~~~~
mute -s, --install  # Installs Newest Mute to System from GitHub
~~~~
