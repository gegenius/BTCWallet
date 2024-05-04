from OPERATIONS import *
import colorama

colorama.init(autoreset=True)

b = Fore.LIGHTBLACK_EX
r = Fore.YELLOW

get = GET
oprint = PRINT

BANNER = f"""
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

"""

class MAIN():
    def __init__(self):
        self.CurrentWallet = None
        self.name = None
    def execute(self, comand):
        comand = comand.split(" ")

        if comand[0] == "wallet":

            if len(comand) == 3:

                if comand[1] == "show":

                    if comand[2] == "current":
                        if self.name != None:
                            oprint.printwalinfo(self, addr=encode('bc', 0, ripemd160_sha256(self.CurrentWallet.public_key)))
                        else:
                            print(Fore.RED + "[ERR] Nessun wallet sellezionato")
                    elif comand[2] == "list":
                        oprint.printwallist(self)
                    else:
                        print(Fore.RED + "[ERR] Parametri errati")

                elif comand[1] == "delate":
                    oprint.delwallet(self, comand[2])
                elif comand[1] == "create":
                    oprint.createwallet(self, comand[2])
                elif comand[1] == "set":
                    oprint.setwallet(self, comand[2])
                else:
                    print(Fore.RED + "[ERR] Parametri errati")

            elif len(comand) == 2:

                if comand[1] == "credit":
                    if self.name != None:
                        oprint.printcredit(self)
                    else:
                        print(Fore.RED + "[ERR] Nessun wallet sellezionato")
                else:
                    print(Fore.RED + "[ERR] Parametri errati")

            else:
                print(Fore.RED + "[ERR] Parametri errati")

        elif comand[0] == "transaction":

            if comand[1] == "send":
                if self.name != None:
                    oprint.send(self, int(comand[3]), comand[2])
                else:
                    print(Fore.RED + "[ERR] Nessun wallet sellezionato")
            elif comand[1] == "show":
                if self.name != None:
                    oprint.printtrans(self)
                else:
                    print(Fore.RED + "[ERR] Nessun wallet sellezionato")
            else:
                print(Fore.RED + "[ERR] Parametri errati")

        elif comand[0] == "exit":
            os.system("cls")
            sys.exit()

        else:
            print(Fore.RED + "[ERR] Comando non trovato")

Main = MAIN()
SETNODE = setnode()

def shell():
    os.system("cls")
    print(BANNER)
    while True:
        i = input(Fore.LIGHTBLACK_EX + ".>" + Fore.RESET)
        Main.execute(i)

def comline():
    status = True
    comand = sys.argv
    comand.pop(0)
    if not ("wallet" in comand and "show" in comand and "list" in comand) and not ("wallet" in comand and "create" in comand):
        wal = comand[0]
        comand.pop(0)
        if wal in os.listdir(".\\database\\"):
            Main.execute("wallet set " + wal)
        else:
            print(Fore.RED + "[ERR] Wallet inesistente")
            status = False
    if status == True:
        Main.execute(" ".join(comand))


if len(sys.argv) == 1:
    shell()
elif len(sys.argv) == 2 and sys.argv[1] == "privnode":
    SETNODE.main()
    shell()
else:
    comline()