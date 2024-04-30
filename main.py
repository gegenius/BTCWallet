from decimal import Decimal
from bit import PrivateKeyTestnet as P
from bit.base32 import encode
from bit.crypto import ripemd160_sha256
import os
import sys
import colorama
from blockcypher import get_address_overview as INFO
from blockcypher import get_transaction_details as T
from colorama import Fore
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

colorama.init(autoreset=True)
b = Fore.LIGHTBLACK_EX
r = Fore.YELLOW


def make_password(password, solt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=solt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

class OPERATIONS():

    def printwalinfo(self, addr):
        print(Fore.GREEN + "[*] Richiesta dati...")
        data = None
        try:
            data = INFO(addr)
        except:
            print(Fore.RED + "[ERR] Errore nella connessione alla blockchain")
        if data != None:
            print(f"""{Fore.GREEN}########## WALLET INFORMATION ##########

{Fore.GREEN}address....................: {Fore.BLUE}{addr}
{Fore.GREEN}credit.....................: {Fore.BLUE}{Decimal(str(data['balance'] / 100000000))} BTC
{Fore.GREEN}total transactions.........: {Fore.BLUE}{data['n_tx']}
{Fore.GREEN}total received.............: {Fore.BLUE}{Decimal(str(data['total_received'] / 100000000))} BTC 
{Fore.GREEN}total sent.................: {Fore.BLUE}{Decimal(str(data['total_sent'] / 100000000))} BTC
{Fore.GREEN}
########################################""")


    def createwallet(self, name):
        print(Fore.GREEN + "[*] Creating wallet...")
        try:
            wal = P()
            print(Fore.GREEN + "[*] Extracting and saving keys...")
            addr = wal.address
            key = wal.to_wif()
            i = input(Fore.GREEN + "[*] Impostare password: ")
            print(Fore.GREEN + "[*] Writing data...")
            file = open('.\\database\\' + name, "w+")
            file.write(addr + "\n" + Fernet(make_password(i.encode(), solt=b'\xef\xd3\xd5\x85\\V\xc7\xd2\xbe\xd89~K\xef8d')).encrypt(key.encode()).decode())
            file.close()
            print(Fore.GREEN + "###### OPERAZIONE COMOPLETATA ######")
            print(f"""{Fore.GREEN}
address........:{Fore.BLUE} {addr}
{Fore.GREEN}wif............:{Fore.BLUE} {key}
{Fore.GREEN}
####################################""")
        except:
            print(Fore.RED + "[ERR] Impossibile generare il wallet bitcoin...")


    def printwalletlist(self):
        data = os.listdir(".\\database\\")
        print(Fore.GREEN + "########## LISTA WALLET ############\n")
        for x in data:
            print(f"{Fore.GREEN}[*] {Fore.BLUE}{x}")
        print(Fore.GREEN + "\n####################################")

    def openwallet(self, name):
        data = os.listdir(".\\database\\")
        if name in data:
            file = open(".\\database\\" + name, "r")
            info = file.read().split("\n")
            file.close()
            if len(info) == 2:
                key = info[1]
                while True:
                    i = input(Fore.GREEN + "[*] Inserire password: ")
                    if i == "exit":
                        break
                    try:
                        key = Fernet(make_password(i.encode(), solt=b'\xef\xd3\xd5\x85\\V\xc7\xd2\xbe\xd89~K\xef8d')).decrypt(key.encode()).decode()
                        break
                    except:
                        pass
                    if key == info[1]:
                        print(Fore.YELLOW + "[WARN] Password errata")
                if key != info[1]:
                    try:
                        self.CurrentWallet = P(key)
                        self.name = name
                        print(Fore.GREEN + "[*] Wallet set...")
                    except:
                        print(Fore.RED + "[ERR] Impossibile aprire il wallet")
        else:
            print(Fore.RED + "[ERR] Wallet inesistente")

    def send(self, number, address):
        if self.CurrentWallet.balance_as("eur") >= number:
            transaction_address = self.CurrentWallet.send([address, number, "eur"])
            print(Fore.GREEN + "[*] TRANSAZIONE ESEGUITA\n[*] Transaction address link..........:" + Fore.BLUE + " https://blockchain.info/tx/" + transaction_address)
        else:
            print(Fore.RED + f"[ERR] Credito insufficente ({ str(self.CurrentWallet.balance_as('eur')) })")

    def printcredit(self):
        print(Fore.GREEN + "[*] Il tuo credito attuale sul wallet '" + self.name + "' corrisponde a " + Fore.BLUE + str(self.CurrentWallet.balance_as("eur")) + "€ (" + str(self.CurrentWallet.balance_as("btc")) + " BTC)")

    def printtrans(self):
        print(Fore.GREEN + "[*] Richiesta dati...")
        trans_addr = None
        try:
            trans_addr = self.CurrentWallet.get_transactions()
        except:
            print(Fore.RED + "[ERR] Errore nella connessione alla blockchain")
        if trans_addr != None:
            print(Fore.GREEN + "########## LISTA TRANSAZIONI ############\n")
            for x in trans_addr:
                fromto = "IN"
                data = T(x)
                for y in data['inputs']:
                    if self.CurrentWallet.address in y['address']:
                        fromto = "OUT"
                print(f"{Fore.GREEN}[*] {Fore.BLUE}{x}{Fore.GREEN} {str(data['confirmed'])} {Fore.BLUE}{fromto}{Fore.GREEN} {Decimal(str(data['total'] / 100000000))} btc")
            print( Fore.GREEN + "\n#########################################")

class MAIN():
    def __init__(self):
        self.name = None
        self.CurrentWallet = None

    def console(self):
        os.system("cls")
        print(f"""
{r}$$$$$$${b}\ {r}$$$$$$$${b}\  {r}$$$$$${b}\  {r}$${b}\      {r}$${b}\           {r}$${b}\ {r}$${b}\            {r}$${b}\{r}     
$${b}  __{r}$${b}\ __{r}$${b}  __|{r}$${b}  __{r}$${b}\ {r}$${b} | {r}${b}\  {r}$${b} |          {r}$${b} |{r}$${b} |           {r}$${b} |{r}    
$${b} |  {r}$${b} |  {r}$${b} |   {r}$${b} /  \__|{r}$${b} |{r}$$${b}\ {r}$${b} | {r}$$$$$${b}\  {r}$${b} |{r}$${b} | {r}$$$$$${b}\ {r}$$$$$${b}\{r}   
$$$$$$${b}\ |  {r}$${b} |   {r}$${b} |      {r}$$ $$ $${b}\{r}$${b} | \____{r}$${b}\ {r}$${b} |{r}$${b} |{r}$${b}  __{r}$${b}\\_{r}$${b}  _|  {r}
$${b}  __{r}$${b}\   {r}$${b} |   {r}$${b} |      {r}$$$${b}  _{r}$$$${b} | {r}$$$$$$${b} |{r}$${b} |{r}$${b} |{r}$$$$$$$${b} | {r}$${b} |{r}    
$${b} |  {r}$${b} |  {r}$${b} |   {r}$${b} |  {r}$${b}\ {r}$$${b}  / \{r}$$${b} |{r}$${b}  __{r}$${b} |{r}$$ {b}|{r}$${b} |{r}$${b}   ____| {r}$${b} |{r}$${b}\{r} 
$$$$$$${b}  |  {r}$${b} |   \{r}$$$$$${b}  |{r}$${b}  /   \{r}$${b} |\{r}$$$$$$${b} |{r}$${b} |{r}$${b} |\{r}$$$$$$${b}\  \{r}$$$${b}  |{r}
{b}\_______/   \__|    \______/ \__/     \__| \_______|\__|\__| \_______|  \____/ 

VERSION 0.1 (alfa)
By g3.genius

""")
        while True:
            comand = input(".> ")
            self.execute(comand)

    def execute(self, comand):
        comand = comand.split(" ")

        if comand[0] == "wallet":
            self.wallet(comand)
        elif comand[0] == "transaction":
            self.transaction(comand)
        elif comand[0] == "exit" and len(comand) == 1:
            exit()
        else:
            print(Fore.RED + "[ERR] Comando non trovato")


    def wallet(self, comand):
        if len(comand) == 3:
            if comand[1] == "show":
                if comand[2] == "current":
                    if self.name != None:
                        OPERATIONS.printwalinfo(self, encode('bc', 0, ripemd160_sha256(self.CurrentWallet.public_key)))
                    else:
                        print(Fore.RED + "[ERR] Nessun wallet selezionato")
                elif comand[2] == "list":
                    OPERATIONS.printwalletlist(self)
                else:
                    print(Fore.RED + "[ERR] Parametri non validi")
            elif comand[1] == "create":
                OPERATIONS.createwallet(self, name=comand[2])
            elif comand[1] == "set":
                OPERATIONS.openwallet(self, name=comand[2])
            else:
                print(Fore.RED + "[ERR] Parametri non validi")
        elif len(comand) == 2:
            if comand[1] == "credit":
                if self.name != None:
                    OPERATIONS.printcredit(self)
                else:
                    print(Fore.RED + "[ERR] Nessun wallet selezionato")
            else:
                print(Fore.RED + "[ERR] Parametri non validi")
        else:
            print(Fore.RED + "[ERR] Parametri mancanti")

    def transaction(self, comand):
        if type(self.CurrentWallet) != None:
            if comand[1] == "send" and len(comand) == 4:
                OPERATIONS.send(self, comand[2], comand[3])
            elif comand[1] == "show":
                if len(comand) == 2:
                    OPERATIONS.printtrans(self)
                else:
                    print(Fore.RED + "[ERR] Parametri non validi")
            else:
                print(Fore.RED + "[ERR] Parametri non validi")
        else:
            print(Fore.RED + "[ERR] Nessun wallet selezionato")

bo = MAIN()
if len(sys.argv) == 1:
    bo.console()
else:
    status = True
    comand = sys.argv
    comand.pop(0)
    if not ("wallet" in comand and "show" in comand and "list" in comand) and not ("wallet" in comand and "create" in comand):
        wal = comand[0]
        comand.pop(0)
        if wal in os.listdir(".\\database\\"):
            bo.wallet([None, "set", wal])
        else:
            print(Fore.RED + "[ERR] Wallet inesistente")
            status = False
    if status == True:
        bo.execute(" ".join(comand))