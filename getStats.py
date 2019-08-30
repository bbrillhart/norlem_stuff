"""
Copyright (c) Norlem Technology Consulting, Inc. <https://www.norlemtc.com>
Palo Alto Networks Traps & XDR Investigation & Response (c) Palo Alto Networks Inc.

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


Purpose:
This is an example script intended to demonstrate the Python scripting features
availale within Palo Alto Networks XDR Investigation & Response and Traps 6.1.x.

Description:
This script will quickly produce a report containing relevant endpoint details
to aid in an investigation. The data collected can be used to detect active
connections, patching levels, uptime, Traps protection status, Traps versioning,
detect persistence attempts, as well review network/system details.

Usage:
To use this script save it to your hard drive simply initiate a 'Live Terminal' 
session with a Traps agent version 6.1.0 or higher. Navigate to 'Python', click 
on the load icon in the upper-right section of the screen and select this script.
Press Shift+Enter to execute the script.

Notes:
Version:        1.1
Author:         Bobby Brillhart <bbrillhart@norlemtc.com>
Creation Date:  05/05/2019 04:04PM CDT 
Purpose/Change: Added Scheduled Tasks/Updated Comments
"""



print("\n\n\n\n\n\n\n\n\n\n\n\n")
print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
print("!!!!!!!!!!!!!!!!!!      S      T      O      P      !!!!!!!!!!!!!!!!!!!")
print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
print("\n")
print("******   R e s u l t s   a r e   b e l o w   t h i s   l i n e   ******")
print("=======================================================================")

from subprocess import check_output

cytool = "C:\Program Files\Palo Alto Networks\Traps\cytool.exe"

def dumpRunKeys(rootKey):
    import winreg

    registryConnection = winreg.ConnectRegistry(None, winreg.HKEY_USERS)
    hiveKeyRoot = winreg.OpenKey(registryConnection, "")

    for key in range(1024):
        try:
            keyName = winreg.EnumKey(hiveKeyRoot, key + 1)
            runKeyName = keyName + rootKey
            runKey = winreg.OpenKey(hiveKeyRoot, runKeyName)
            print("\n" + runKeyName)

            for keys in range(1024):
                try:
                    runKeyValue = winreg.EnumValue(runKey, keys)
                    print("      " + runKeyValue[0] + " --- " + runKeyValue[1])

                except WindowsError:
                    break

        except WindowsError:
            break

    return


print("\n\n***          S y s t e m   I n f o r m a t i o n          ***")
print(check_output("systeminfo", shell=True).decode())
print("\n\n***           T r a p s   I n f o r m a t i o n           ***\n")
print("Traps Version Information:")
print("--------------------------")
print(check_output([cytool, "info", "query"], shell=True).decode())
print("Traps ML Model Information:")
print("---------------------------")
print(check_output([cytool, "tla", "query"], shell=True).decode())
print("Current Injected Processes:")
print("-----------------------------")
print(check_output([cytool, "enum"], shell=True).decode())
print("\n***          S o c k e t   I n f o r m a t i o n          ***")
print(check_output(["netstat", "-bano"], shell=True).decode())
print("\n***     R u n   &   R u n O n c e   K e y s   D u m p     ***")
dumpRunKeys("\Software\Microsoft\Windows\CurrentVersion\Run")
dumpRunKeys("\Software\Microsoft\Windows\CurrentVersion\RunOnce")
print("\n***        S c h e d u l e d  T a s k s  D u m p          ***")
print(check_output(["schtasks", "/query"], shell=True).decode())
