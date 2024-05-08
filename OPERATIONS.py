"""
import delle librerie principali
"""

import os
import sys
from decimal import Decimal
from colorama import Fore
import base64

"""
import delle librerie della criptografia
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

"""
import librerie per interagire con la blockchain
"""

from bit import PrivateKeyTestnet as P
from bit.base32 import encode
from bit.crypto import ripemd160_sha256
from bit.network import NetworkAPI
from blockcypher import get_address_overview as INFO
from blockcypher import get_transaction_details as T

NETAPI = None

class GET():
    def trueorfalse(self, errmess, entrymess):
        while True:
            i = input(entrymess)
            if i == "y":
                return True
            elif i == "n":
                return False
            else:
                print(errmess)

    def make_password(self, password, solt):
        """
        :param password: byte of password
        :param solt: random byte to make difficult bruteforce
        :return: byte of key in base64
        """
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=solt, iterations=100000, backend=default_backend())
        return base64.urlsafe_b64encode(kdf.derive(password))

    def wallinfo(self, addr):
        """
        :param addr: wallet address in sha256
        :return: list of wallet informations
        """
        try:
            data = INFO(addr)
        except:
            data = 0
        return data

    def makewallet(self):
        """
        :return addr: string of public address to send bitcoin
        :retutn key: string of wif to access at the wallet
        """
        try:
            wal = P()
        except:
            key = None
            addr = None
        else:
            key = wal.to_wif()
            addr = wal.address
        return key, addr

    def wallist(self):
        """
        :return: list with wallets names
        """
        data = os.listdir(".\\")
        out = []
        for x in data:
            if "wal" == x.split(".")[-1]:
                out.append(x)
        return out

    def is_wallet(self, wallet):
        """
        :param wallet: strng with name of wallet
        :return: bool
        """
        if wallet in GET.wallist(self):
            return True
        else:
            return False

    def send(self, addr, value):
        """
        :param addr: string of address
        :param value: int of eur to send
        :return: 0 = "error" 1 = "no money"
        """
        if self.CurrentWallet.balance_as("eur") >= value:
            try:
                transaction_address = self.CurrentWallet.send([addr, value, "eur"])
                return transaction_address
            except:
                return 0
        else:
            return 1

    def walltransactions(self):
        """
        :return: list (string) of transactions id
        """
        return self.CurrentWallet.get_transactions()

    def transactioninfo(self, transid):
        """
        :param transid: string of transaction id
        :return: list of transaction informations
        """
        return T(transid)

    def getwaladdrkey(self, name, cryptokey):
        """
        :param name: string of name
        :param cryptokey: byte of cryptography key in base64
        :return: string of addr and string of wif key
        """
        if GET.is_wallet(self, name):
            file = open(".\\" + name, "r")
            data = file.read()
            file.close()
            data = data.split("\n")
            addr = data[0]
            try:
                key = Fernet(cryptokey).decrypt(data[1].encode())
            except:
                key = None
            return addr, key

    def openwallet(self, key, name):
        """
        :param key: string of wif key
        :return: True or False
        """
        try:
            w = P(key)
        except:
            return False
        else:
            self.CurrentWallet = w
            self.name = name
            return True


class PRINT():

    def printwallist(self):
        data = GET.wallist(self)
        print(Fore.GREEN + "########## LISTA WALLET ############\n")
        for x in data:
            print(f"{Fore.GREEN}[*] {Fore.BLUE}{x}")
        print(Fore.GREEN + "\n####################################")

    def printwalinfo(self, addr):
        """
        :param addr: string of wallet address
        """
        print(Fore.GREEN + "[*] Richiesta dati...")
        try:
            data = GET.wallinfo(self, addr)
        except:
            print(Fore.RED + "[ERR] Errore nella connessione alla blockchain")
        else:
            if data != 0:
                print(f"""{Fore.GREEN}########## WALLET INFORMATION ##########

{Fore.GREEN}address....................: {Fore.BLUE}{encode('bc', 0, ripemd160_sha256(self.CurrentWallet.public_key))}
{Fore.GREEN}credit.....................: {Fore.BLUE}{Decimal(str(data['balance'] / 100000000))} BTC
{Fore.GREEN}total transactions.........: {Fore.BLUE}{data['n_tx']}
{Fore.GREEN}total received.............: {Fore.BLUE}{Decimal(str(data['total_received'] / 100000000))} BTC 
{Fore.GREEN}total sent.................: {Fore.BLUE}{Decimal(str(data['total_sent'] / 100000000))} BTC
{Fore.GREEN}
#######################################""")
            else:
                print(Fore.RED + "[ERR] Errore nella connessione alla blockchain")

    def createwallet(self, name):
        """
        :param name: string of name to get for the new wallet
        """
        print(Fore.GREEN + "[*] Creating wallet...")
        key, addr = GET.makewallet(self)
        if key != None and addr != None:
            print(Fore.GREEN + "[*] Saving keys...")
            i = input(Fore.GREEN + "[*] Impostare password: ")
            print(Fore.GREEN + "[*] Writing data...")
            if not GET.is_wallet(self, name):
                file = open('.\\' + name, "w+")
                file.write(addr + "\n" + Fernet(GET.make_password(self, i.encode(), solt=b'\xef\xd3\xd5\x85\\V\xc7\xd2\xbe\xd89~K\xef8d')).encrypt(key.encode()).decode())
                file.close()
                print(Fore.GREEN + "###### OPERAZIONE COMOPLETATA ######")
                print(f"""{Fore.GREEN}
address........:{Fore.BLUE} {addr}
{Fore.GREEN}wif............:{Fore.BLUE} {key}
{Fore.GREEN}
####################################""")
            else:
                print(Fore.RED + "[ERR] Wallet gia esistente")
        else:
            print(Fore.RED + "[ERR] Errore nella creazione del wallet")

    def transinfo(self, addr):
        """
        :param addr: string of wallet address
        """
        data = GET.transactioninfo(self, addr)
        print(data)

    def send(self, number, address):
        """
        :param number: int of number to send
        :param address: string of wallet address
        """
        response = GET.send(self, address, number)
        if response == 1:
            print(Fore.RED + f"[ERR] Credito insufficente ({str(self.CurrentWallet.balance_as('eur'))}€)")
        if response == 0:
            print(Fore.RED + "[ERR] Impossibile eseguire la transazione")
        else:
            print(Fore.GREEN + "[*] Ricerca dati transazione...")
            data = PRINT.transinfo(response)
            print(Fore.GREEN + "######### TRANSACRION INFO #########\n")
            print(data)
            print(Fore.GREEN + "\n####################################")

    def printcredit(self):
        print(Fore.GREEN + "[*] Il tuo credito attuale sul wallet '" + self.name + "' corrisponde a " + Fore.BLUE + str(self.CurrentWallet.balance_as("eur")) + "€ (" + str(self.CurrentWallet.balance_as("btc")) + " BTC)")

    def printtrans(self):
        print(Fore.GREEN + "[*] Richiesta dati...")
        try:
            trans_addr = GET.walltransactions(self)
        except:
            print(Fore.RED + "[ERR] Errore nella connessione alla blockchain")
        else:
            print(Fore.GREEN + "########## LISTA TRANSAZIONI ############\n")
            for x in trans_addr:
                PRINT.transinfo(x)
            print( Fore.GREEN + "\n#########################################")

    def setwallet(self, name):
        """
        :param name: string of wallet name
        """
        if GET.is_wallet(self, name):
            while True:
                i = input(Fore.GREEN + "[*] Inserire password: ")
                if i != "exit":
                    addr, key = GET.getwaladdrkey(self, name, GET.make_password(self, i.encode(), b'\xef\xd3\xd5\x85\\V\xc7\xd2\xbe\xd89~K\xef8d'))
                    if key != None:
                        break
                    else:
                        print(Fore.YELLOW + "[WARN] Password errata")
                else:
                    key = None
                    break
            if key != None:
                response = GET.openwallet(self, key.decode(), name)
                if response == True:
                    print(Fore.GREEN + "[*] Wallet set...")
                else:
                    print(Fore.RED + "[ERR] Errore nell'apertura del wallet")
        else:
            print(Fore.RED + "[ERR] Wallet inesistente")


class setnode():

    def main(self):
        os.system("cls")
        setconf = GET.trueorfalse(self, Fore.YELLOW + "[WARN] Valore non valido (y/n)", Fore.GREEN + "[*] Importare file di configurazione? (y/n)")
        if setconf == False:
            data = self.setnodemanual()
            saveconf = GET.trueorfalse(self, Fore.YELLOW + "[WARN] Valore non valido (y/n)", Fore.GREEN + "[*] Salvare configurazione in un file? (y/n)")
            if saveconf == True:
                self.saveconf(data)
        else:
            name = input(Fore.GREEN + "[*] Inserire il path del file: ")
            self.setnodefromfile(name)

    def setnodemanual(self):
        global NETAPI
        print(Fore.GREEN + "[*] CONFIGURING NODE CONNECTION")
        host = input(Fore.GREEN + "[*] Host address (IPv4): ")
        while True:
            port = input(Fore.GREEN + "[*] Port: ")
            try:
                port = int(port)
            except:
                print(Fore.YELLOW + "[WARN] Valore non valido")
            else:
                if port > 65535:
                    print(Fore.YELLOW + "[WARN] Valore non valido")
                else:
                    break
        user = input(Fore.GREEN + "[*] Username: ")
        password = input(Fore.GREEN + "[*] Password: ")
        use_https = GET.trueorfalse(self, Fore.YELLOW + "[WARN] Valore non valido (y/n)", Fore.GREEN + "[*] HTTPS (y/n): ")
        try:
            NETAPI = NetworkAPI()
            NETAPI.connect_to_node(host=host, port=port, user=user, password=password, use_https=use_https, testnet=False)
            NETAPI.get_transaction_by_id("f2c94af86d00d0c87a391c4e3cb783431a737315bf23c2c7531238eec6e81032")
        except:
            print(Fore.RED + "[ERR] Impossibile connettersi al nodo")
            exit()
        else:
            print(Fore.GREEN + "[*] BITCOIN IMPOSTATO CON SUCCESSO")
            return {'password': password, 'username': user, 'host': host, 'port': port,'use_https': use_https}


    def saveconf(self, data):
        content = f"{data['password']}\n{data['username']}\n{data['host']}\n{str(data['port'])}\n{str(data['https'])}".encode()
        file = open(data['host'] + ".node", "wb+")
        file.write(content)
        file.close()
        print(Fore.GREEN + "[*] Configurazione salvata con successo nel file '" + data['host'] + ".node'...")

    def setnodefromfile(self, path):
        try:
            file = open(path, "rb")
        except:
            print(Fore.RED + "[ERR] Impossibile trovare il file")
        else:
            data = file.read().decode().split("\n")
            file.close()
            if len(data) != 4:
                if data[4] == str(True):
                    data[4] = True
                else:
                    data[4] = False
                try:
                    NetworkAPI.connect_to_node(password=data[0], user=data[1], host=data[2], port=int(data[3]), use_https=data[4], testnet=False)
                except:
                    print(Fore.RED + "[ERR] Impossibile connettersi al nodo")
                    sys.exit()
                else:
                    print(Fore.GREEN + "[*] BITCOIN IMPOSTATO CON SUCCESSO")
            else:
                print(Fore.RED + "[ERR] File malformato")