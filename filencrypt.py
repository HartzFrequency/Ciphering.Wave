import colorama
from colorama import Fore, Style            # Importing colorama for terminal text coloring
from colorama.initialise import reset_all   # Importing colorama for terminal text coloring

import hashlib                              # Importing hashlib for additional hash functions
from hashlib import sha256                  # Importing hashlib for secure hash functions
from discord_webhook import DiscordWebhook, DiscordEmbed 
# Importing DiscordWebhook and DiscordEmbed for interacting with Discord webhooks
from Cryptodome.Cipher import AES 
# Importing AES from Cryptodome.Cipher for encryption and decryption operations
from Cryptodome.Util import Padding
# Importing Padding from Cryptodome.Util for data padding in encryption

import urllib.request                       # Importing urllib.request for making HTTP requests
from urllib.request import Request
# Importing Request from urllib.request for making HTTP requests
import pyfiglet                             # Importing pyfiglet for creating ASCII art text
import argparse                             # Importing argparse for parsing command line arguments
import random                               # Importing random for generating random values
import timeit                               # Importing timeit for measuring execution time of code
import string                               # Importing string for string manipulation operations
import time                                 # Importing time for time-related operations
import sys                                  # Importing sys for system-specific functionality
import os                                   # Importing os for operating system-related functionality
from art import text2art                    # Importing text2art from art for creating ASCII art text



def banner():   # This function creates the home screen Design/Pattern
    try:
        pfbanner = pyfiglet.figlet_format("                   Ciphering.Wave", font="digital")
        print(pfbanner)
        print("                          Submitted By:")
        print("                 Abhishek Rajput (0901CS211003)")
        print("                   Akhil Jain (0901CS211013)")
        print("                Harsh Shrivastava (0901CS211049)")
        print("          https://github.com/HartzFrequency/Ciphering.Wave")
    except pyfiglet.FontNotFound:
        sys.exit(Fore.RED + "\n[-]" + Style.RESET_ALL + " Error - Banner error. Run 'sudo pip3 install --upgrade pyfiglet' and re-try.")

def menu():     # This function shows us the menu of homescreen
    print("\n\nMenu")
    print("[1] Encrypt")
    print("[2] Decrypt")
    print("[3] Informations")
    print("[4] Contact dev")

def encryption():
    def filencrypt(pswd, iv, file):
        # Derive a key from the provided password using SHA-256
        key = hashlib.sha256(pswd.encode()).digest()

        # Save the initialization vector (IV) to a file for future decryption reference
        with open("AES_IV.txt", "w") as ivf:
            ivf.write(f"Encryption of : {file}\n\n-----BEGIN AES INITIALIZATION VECTOR BLOCK-----\n{iv}\n-----END AES INITIALIZATION VECTOR BLOCK-----".replace("b'", "").replace("'", ""))

        # Read the content of the file to be encrypted
        with open(file, "rb") as f:
            data = f.read()

        # Record the start time for measuring encryption duration
        stime = timeit.default_timer()

        # Initialize AES cipher in CBC mode with the derived key and provided IV
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Pad the data to meet the block size requirement
        paddeddata = Padding.pad(data, 16)

        # Encrypt the padded data
        encrypteddata = cipher.encrypt(paddeddata)

        # Write the encrypted data back to the original file
        with open(file, "wb") as ef:
            ef.write(encrypteddata)

        # Calculate and print the encryption duration
        time = timeit.default_timer() - stime
        print(Fore.GREEN + "\n[+]" + Style.RESET_ALL + " Encryption of the file " + Fore.GREEN + str(file) + Style.RESET_ALL + " complete in " + Fore.GREEN + str(round(time, 3)) + Style.RESET_ALL + " seconds!\n")

        # Provide additional information for the user
        print("Don't forget the password you used for the encryption of this file!\nAlso a " + Fore.GREEN + "AES_IV.txt " + Style.RESET_ALL + "file has been created, it contains the initialization vector (IV) of the encryption. " + Fore.RED + "\nYou have to keep this file " + Style.RESET_ALL + "because you will need this IV for decrypt your file.")

    # Prompt user for the file to encrypt
    file = input(Fore.YELLOW + "\nFile to encrypt : " + Style.RESET_ALL)

    # Check if the file has an extension
    if "." in file:
        pass
    else:
        # Exit with an error message if the file is missing an extension
        sys.exit(Fore.RED + "\n[-]" + Style.RESET_ALL + " Error - Missing extension")

    # Attempt to open the file in binary mode to check its existence
    try:
        with open(file, "rb"):
            pass
    except IOError:
        # Exit with an error message if the file is not found
        sys.exit(Fore.RED + "\n[-]" + Style.RESET_ALL + f" Error - File not found. Make sure your file is in this path : {os.path.realpath(__file__).replace('filencrypt.py', '')}")

    # Check if the file size exceeds the maximum allowed size (60 MB)
    if os.path.getsize(file) > 62914560:
        # Exit with an error message if the file is too large
        sys.exit(Fore.RED + "\n[-]" + Style.RESET_ALL + " Error - File too large. Max size is 60Mo to avoid crashes or errors.")
    else:
        pass

    # Prompt user to choose a strong password
    pswd = input(Fore.YELLOW + "Choose a strong password : " + Style.RESET_ALL)

    # Define a function to generate a random initialization vector (IV)
    def geniv(length):
        str = string.ascii_uppercase + string.digits
        return "".join(random.choice(str) for i in range(length))

    # Generate a random IV of length 16
    iv = geniv(16)

    # Encrypt the file using the provided password and generated IV
    filencrypt(pswd, iv.encode(), file)
    
def decryption():
    def filedecrypt(pswd, iv, file):
        # Derive a key from the provided password using SHA-256
        key = hashlib.sha256(pswd.encode()).digest()

        # Read the encrypted data from the file
        with open(file, "rb") as f:
            data = f.read()

        # Record the start time for measuring decryption duration
        stime = timeit.default_timer()

        # Initialize AES cipher in CBC mode with the derived key and provided IV
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Decrypt the data
        decrypteddata = cipher.decrypt(data)

        # Unpad the decrypted data to remove padding
        unpaddeddata = Padding.unpad(decrypteddata, 16)

        # Write the decrypted data back to the original file
        with open(file, "wb") as ef:
            ef.write(unpaddeddata)

        # Calculate and print the decryption duration
        time = timeit.default_timer() - stime
        print(Fore.GREEN + "\n[+]" + Style.RESET_ALL + " Decryption of the file " + Fore.GREEN + str(file) + Style.RESET_ALL + " complete in " + Fore.GREEN + str(round(time, 3)) + Style.RESET_ALL)
    
    # Prompt user for the file to decrypt
    file = input(Fore.YELLOW + "\nFile to decrypt : " + Style.RESET_ALL)

    # Check if the file has an extension
    if "." in file:
        pass
    else:
        # Exit with an error message if the file is missing an extension
        sys.exit(Fore.RED + "\n[-]" + Style.RESET_ALL + " Error - Missing extension")

    # Attempt to open the file in binary mode to check its existence
    try:
        with open(file, "rb"):
            pass
    except IOError:
        # Exit with an error message if the file is not found
        sys.exit(Fore.RED + "\n[-]" + Style.RESET_ALL + " Error - File not found. Make sure your file is in this path : {os.path.realpath(__file__).replace('filencrypt.py', '')}")

    # Prompt user for the password used to encrypt the file
    pswd = input(Fore.YELLOW + f"Password used to encrypt {file} : " + Style.RESET_ALL)

    # Prompt user for the IV (Initialization Vector) used to encrypt the file
    iv = input(Fore.YELLOW + f"IV used to encrypt {file} : " + Style.RESET_ALL)

    # Check if the IV has the correct length (16 characters)
    if len(iv) != 16:
        sys.exit(Fore.RED + "\n[-]" + Style.RESET_ALL + f" Error - Incorrect length of initialization vector : {len(iv)} chars instead of 16.")

    # Decrypt the file using the provided password and IV
    filedecrypt(pswd, iv.encode(), file)


def about():
    print(Fore.YELLOW + f"\n[>] Running file : {os.path.realpath(__file__)}" + Style.RESET_ALL)
    print("\n[>] Presentation\nCiphering Wave is a cryptography project made for Information Security Lab. This encrypts and decrypts your files of all types (js, txt, png...) in AES-256. Ciphering Wave works with a strong password chosen by the user and with a 16 byte initialization vector (IV) generated by the program, you must keep this IV secret and you will need it to decrypt your file. Note that a new IV is created for each encrypted file.")
    print("\n[>] Security\nIs Ciphering Wave a secure project?\Ciphering Wave uses AES-256-bit encryption with Cipher Block Chaining (CBC) mode. Although CBC Mode is less secure than XTS or GCM Modes, it is generally suitable for encrypting more or less sensitive files.\nSecurity also depends on the password you use, you should use a strong password with uppercase, lowercase, symbols and numbers.")
    print("\nIf you have any other questions or suggestions, contact us on discord (frequency.hartz), mail (harshshrivastava554@gmail.com) or by running 'python filencrypt.py -c'!\n")

def contact():
    # Importing 'os' globally for access
    global os

    # Setting up Discord webhook URL
    webhook = DiscordWebhook(url="https://discord.com/api/webhooks/1174817583216726088/1NF3FdBKaxH5jsaMdayOkN2qNEdsl9V8SsWJZ6XN2unTxbk4QNRL1crZPCB7AY-pZjq0")

    # Setting up headers for HTTP request to Discord API
    req = Request(
        url="https://discord.com/api/webhooks/1174817583216726088/1NF3FdBKaxH5jsaMdayOkN2qNEdsl9V8SsWJZ6XN2unTxbk4QNRL1crZPCB7AY-pZjq0",
        headers={"User-Agent": "Mozilla/5.0"}
    )

    try:
        # Trying to open the Discord webhook URL to ensure connectivity
        with urllib.request.urlopen(req) as response:
            txt = response.read()
    except:
        # Exit with an error message if there is a connection error
        sys.exit(Fore.RED + "\n[-]" + Style.RESET_ALL + " Error - Contact system error. Try to contact me by discord (hartz.Frequency) or by mail (harshshrivastava554@gmail.com).")

    # Prompt user for contact information, subject, and message
    contactway = input(Fore.YELLOW + "\nEmail or discord to be contacted : " + Style.RESET_ALL)
    subject = input(Fore.YELLOW + "Subject : " + Style.RESET_ALL)
    message = input(Fore.YELLOW + "Message : " + Style.RESET_ALL)

    # Check for empty inputs and exit with an error message if any are found
    if contactway == "" or subject == "" or message == "":
        sys.exit(Fore.RED + "\n[-]" + Style.RESET_ALL + " Error - Empty inputs")

    # Prompt user for image attachment
    img = input(Fore.YELLOW + "Add an image ('y' or 'n') : " + Style.RESET_ALL)

    if img == "y":
        # Prompt user for image file path
        filepath = input(Fore.YELLOW + "Path of image : " + Style.RESET_ALL)

        try:
            # Attempt to open the image file in binary mode to check its existence
            with open(filepath, 'rb'):
                pass
        except IOError:
            # Exit with an error message if the image file is not found
            sys.exit(Fore.RED + "\n[-]" + Style.RESET_ALL + " Error - Image not found")

        # Check if the image file size exceeds the maximum allowed size (8 MB)
        if os.path.getsize(filepath) > 8388608:
            sys.exit(Fore.RED + "\n[-]" + Style.RESET_ALL + " Error - File too large. Max size is 8Mo.")
        else:
            pass

        # Add the image file to the Discord webhook
        with open(filepath, "rb") as f:
            webhook.add_file(file=f.read(), filename="file.png")
    else:
        pass

    # Create a Discord embed with contact information, subject, and message
    embed = DiscordEmbed(title="Contact Filencrypt", color="03b2f8")
    embed.add_embed_field(name="Moyen de contact", value=contactway, inline=False)
    embed.add_embed_field(name="Sujet", value=subject, inline=False)
    embed.add_embed_field(name="Message", value=message, inline=False)

    # Set up a proxy for the Discord webhook (if needed)
    proxy = {
        "http": "14.97.216.232:80"
    }
    webhook.set_proxies(proxy)

    # Add the embed to the Discord webhook and execute the request
    webhook.add_embed(embed)
    response = webhook.execute()

    # Print a success message after the message is sent
    print(Fore.GREEN + "\n[+]" + Style.RESET_ALL + " Message sent with success")


if sys.platform.startswith("linux"):
    os.system("clear")
elif sys.platform.startswith("win32"):
    os.system("cls")
else:
    pass

colorama.init()

parser = argparse.ArgumentParser()
parser.add_argument('-e', help="Encrypt a file", action="store_true")
parser.add_argument('-d', help="Decrypt a file", action="store_true")
parser.add_argument('-i', help="Informations", action="store_true")
parser.add_argument('-c', help="Contact dev", action="store_true")
args = parser.parse_args()

try:
    if args.e:
        banner()
        encryption()

    elif args.d:
        banner()
        decryption()

    elif args.i:
        banner()
        about()

    elif args.c:
        banner()
        contact()
        
    else:
        banner()
        menu()
        choice = input("Choice: ")

        if choice == "1":
            encryption()

        elif choice == "2":
            decryption()

        elif choice == "3":
            about()

        elif choice == "4":
            contact()

        else:
            sys.exit(Fore.RED + "\n[-] " + Style.RESET_ALL + "Error - You must reply '1', '2', '3' or '4'")

except KeyboardInterrupt:
    sys.exit(Fore.RED + "\n[-]" + Style.RESET_ALL + " Error - Filencrypt has been interrupted by user")