import tkinter
from tkinter import *
from tkinter import filedialog as tkFileDialog, constants as tkconstants
import webbrowser
import secure
from Crypto.PublicKey import RSA
import os

def openfileEnc():
	filename = tkFileDialog.askopenfilename(initialdir="/home/parth/Desktop", title="Select file", filetypes=(("text files", "*.txt"), ("all files", "*.*")))
	fileToEncrptyEntryUpdate(filename)


def opendirectoryEnc():
	directory = tkFileDialog.askdirectory(initialdir="/home/parth/Desktop", title="Select directory")
	destinationFolderEncEntryUpdate(directory)


def openfileDec():
	filename = tkFileDialog.askopenfilename(initialdir="/home/parth/Desktop", title="Select file", filetypes=(("text files", "*.txt"), ("all files", "*.*")))
	fileToDecryptEntryUpdate(filename)


def opendirectoryDec():
	directory = tkFileDialog.askdirectory(initialdir="/home/parth/Desktop", title="Select directory")
	destinationFolderDecEntryUpdate(directory)


def sendfilepage():
	webbrowser.open_new(r"http://127.0.0.1:5000/upload-file")


def recievefilepage():
	webbrowser.open_new(r"http://127.0.0.1:5000/file-directory")


def opengithub(event):
	webbrowser.open_new(r"https://github.com/jai2dev")


def fileToEncrptyEntryUpdate(filename):
	inputEncFileEntry.delete(0, END)
	inputEncFileEntry.insert(0, filename)


def destinationFolderEncEntryUpdate(directory):
	inputEncDirEntry.delete(0, END)
	inputEncDirEntry.insert(0, directory)


def fileToDecryptEntryUpdate(filename):
	outputDecFileEntry.delete(0, END)
	outputDecFileEntry.insert(0, filename)


def destinationFolderDecEntryUpdate(directory):
	outputDecDirEntry.delete(0, END)
	outputDecDirEntry.insert(0, directory)


def encryptor():
    EncryptBTN.config(state="disabled")
    public_key = publicKeyOfRecieverEntry.get()
    private_key = privateKeyOfSenderEntry.get()
    directory = inputEncDirEntry.get()
    filename = inputEncFileEntry.get()
    secure.encrypt(filename, directory, public_key, private_key)
    EncryptBTN.config(state="normal")

filename = "encrypt.txt"
directory = "C://Users//dell//Desktop//CLOUD"
public_key = 324655201320946529188557691838483227882748563398767893235568008953648593822588334237936360302893002686412447506175897248466832819633504957323739445621438138855594406276821567658461120889559160225944096790219365223347645123491900315291535446114929929438288741284520587560977434491000434042952327940141145793557759676747464609243690213043798293527791474669772518531261024945045564460232172829298779426355974130508154295052964642410917564376862365685117549782145768909453704490574953597365360195582234482462609859783995195306403666635321920963316887875564617727773331585002405662482004647696860185850410478624406686205393627624191250673743962509604080441421187455654837684213574645818135062892118461873138009840339270758656363907008074631656257260885667312699596350861947123477180707996314019944110583894473670823757686882859119159837372297459824314825353100855849365620942127656896758286533181714193294669587176098453948256097914401872959795135511527160350748599683517059000520092460633657872263650065241185756575888678848106948569472004096243011598004116923338900463898963795498834506787442057344175267347340587113623576906472465566528522893605112377428699614732516876001345274301505280429993631269331251544700245800259296755518523899561985619341645254269399838313632951228863555252969134932771732309427478104229715581343450638183616305237575420920281937767844086290629545791315115315072355782281630406974438567220657176338401087387594256167991261105496610139546814335688396013888204691705141359323294310957719627071163931229175433790635744005118660448713853055178562379816709336307838775714969436936239677396284009185393040910806616381060503062132264350158778932823180831158277513050664517442350477773276667120448245773397317217208621560029689690083279628893922655072908094321600356752059184557725118704581100246181903062693285134506052160431370937488136115367016176127686130312060532553472218869781783280783568988559062785572606332264378002050203137579223200790163527771996187863564342890405246784926241775595274211149446999951958457283825920822474109457681287097453515368367673969109322753609120425845549656243619302072293275812346318744998513926285734604636398187150509237968161030405577600581376448171158729647254937349301820452905853595658051147393599354572894936700768251467728125580711531783063347808485140852225585712883874632564936245570724116339842432530637541960494310159635763265815457365416859909553810462808921358549875237471405564815239340162161426449
private_key = 4024535583167352501821734616350


def validate_public_key(public_key):
    """Validate a public key."""
    if not isinstance(public_key, int) or public_key <= 0:
        return False
    return True

def validate_private_key(private_key):
    """Validate a private key."""
    if not isinstance(private_key, int) or private_key <= 0:
        return False
    return True

def public_key_to_openssh(public_key):
    """Convert a public key to OpenSSH format."""
    key = RSA.construct((public_key >> 16) & 0xFFFFFFFF, public_key & 0xFFFFFFFF)
    return key.exportKey('OpenSSH').decode('utf-8')

def decrypt(filename, directory, public_key, private_key):
    """Decrypt a file."""
    # Load the private key
    private_key_obj = RSA.importKey(str(private_key).encode('utf-8'))

    # Load the public key
    public_key_obj = RSA.importKey(public_key_to_openssh(int(public_key)))

    # Get the full path of the encrypted file
    encrypted_file = os.path.join(directory, filename)

    # Decrypt the file
    with open(encrypted_file, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = private_key_obj.decrypt(encrypted_data)

    # Get the directory and filename for the decrypted file
    decrypted_filename = 'decrypted_' + filename
    decrypted_file = os.path.join(directory, decrypted_filename)

    # Write the decrypted data to a file
    with open(decrypted_file, 'wb') as f:
        f.write(decrypted_data)

    return decrypted_file
filename = "decrypt.txt"
directory = "C://Users//dell//Desktop//CLOUD"
public_key = 324655201320946529188557691838483227882748563398767893235568008953648593822588334237936360302893002686412447506175897248466832819633504957323739445621438138855594406276821567658461120889559160225944096790219365223347645123491900315291535446114929929438288741284520587560977434491000434042952327940141145793557759676747464609243690213043798293527791474669772518531261024945045564460232172829298779426355974130508154295052964642410917564376862365685117549782145768909453704490574953597365360195582234482462609859783995195306403666635321920963316887875564617727773331585002405662482004647696860185850410478624406686205393627624191250673743962509604080441421187455654837684213574645818135062892118461873138009840339270758656363907008074631656257260885667312699596350861947123477180707996314019944110583894473670823757686882859119159837372297459824314825353100855849365620942127656896758286533181714193294669587176098453948256097914401872959795135511527160350748599683517059000520092460633657872263650065241185756575888678848106948569472004096243011598004116923338900463898963795498834506787442057344175267347340587113623576906472465566528522893605112377428699614732516876001345274301505280429993631269331251544700245800259296755518523899561985619341645254269399838313632951228863555252969134932771732309427478104229715581343450638183616305237575420920281937767844086290629545791315115315072355782281630406974438567220657176338401087387594256167991261105496610139546814335688396013888204691705141359323294310957719627071163931229175433790635744005118660448713853055178562379816709336307838775714969436936239677396284009185393040910806616381060503062132264350158778932823180831158277513050664517442350477773276667120448245773397317217208621560029689690083279628893922655072908094321600356752059184557725118704581100246181903062693285134506052160431370937488136115367016176127686130312060532553472218869781783280783568988559062785572606332264378002050203137579223200790163527771996187863564342890405246784926241775595274211149446999951958457283825920822474109457681287097453515368367673969109322753609120425845549656243619302072293275812346318744998513926285734604636398187150509237968161030405577600581376448171158729647254937349301820452905853595658051147393599354572894936700768251467728125580711531783063347808485140852225585712883874632564936245570724116339842432530637541960494310159635763265815457365416859909553810462808921358549875237471405564815239340162161426449
private_key = 4024535583167352501821734616350



def main():
	global filename
	global directory

	filename = ""
	directory = ""

	global form
	form = tkinter.Tk()
	form.wm_title('Secure File Transfer')

	EncryptStep = LabelFrame(form, text=" 1. File Encryption: ")
	EncryptStep.grid(row=0, columnspan=7, sticky='W', padx=5, pady=5, ipadx=5, ipady=5)

	DecryptStep = LabelFrame(form, text=" 2. File Decryption: ")
	DecryptStep.grid(row=2, columnspan=7, sticky='W', padx=5, pady=5, ipadx=5, ipady=5)

	Aboutus = LabelFrame(form, text=" About ")
	Aboutus.grid(row=0, column=9, columnspan=2, rowspan=8, sticky='NS', padx=5, pady=5)

	menu = Menu(form)
	form.config(menu=menu)

	menufile = Menu(menu)
	menufile.add_command(label='Send file', command=lambda: sendfilepage())
	menufile.add_command(label='Recieve file', command=lambda: recievefilepage())
	menufile.add_command(label='Exit', command=lambda: exit())
	menu.add_cascade(label='Menu', menu=menufile)

	global inputEncFileEntry
	global inputEncDirEntry
	global publicKeyOfRecieverEntry
	global privateKeyOfSenderEntry

	global EncryptBTN

	inputEncFile = Label(EncryptStep, text="Select the File:")
	inputEncFile.grid(row=0, column=0, sticky='E', padx=5, pady=2)

	inputEncFileEntry = Entry(EncryptStep)
	inputEncFileEntry.grid(row=0, column=1, columnspan=7, sticky="WE", pady=3)

	inputEncBtn = Button(EncryptStep, text="Browse ...", command=openfileEnc)
	inputEncBtn.grid(row=0, column=8, sticky='W', padx=5, pady=2)
	inputEncDir = Label(EncryptStep, text="Save File to:")
	inputEncDir.grid(row=1, column=0, sticky='E', padx=5, pady=2)

	inputEncDirEntry = Entry(EncryptStep)
	inputEncDirEntry.grid(row=1, column=1, columnspan=7, sticky="WE", pady=2)

	inputEncDirBtn = Button(EncryptStep, text="Browse ...", command=opendirectoryEnc)
	inputEncDirBtn.grid(row=1, column=8, sticky='W', padx=5, pady=2)
	publicKeyOfReciever = Label(EncryptStep, text="Public-Key of reciever:")
	publicKeyOfReciever.grid(row=2, column=0, sticky='E', padx=5, pady=2)

	publicKeyOfRecieverEntry = Entry(EncryptStep)
	publicKeyOfRecieverEntry.grid(row=2, column=1, sticky='E', pady=2)
	privateKeyOfSender = Label(EncryptStep, text="Private-Key of sender:")
	privateKeyOfSender.grid(row=2, column=5, padx=5, pady=2)

	privateKeyOfSenderEntry = Entry(EncryptStep)
	privateKeyOfSenderEntry.grid(row=2, column=7, pady=2)
	EncryptBTN = tkinter.Button(EncryptStep, text="Encrypt   ", command=encryptor)
	EncryptBTN.grid(row=2, column=8, sticky='W', padx=5, pady=2)

	global outputDecFileEntry
	global outputDecDirEntry
	global publicKeyOfSenderEntry
	global privateKeyOfRecieverEntry

	global DecryptBTN
	outputDecFile = Label(DecryptStep, text="Select the File:")
	outputDecFile.grid(row=0, column=0, sticky='E', padx=5, pady=2)

	outputDecFileEntry = Entry(DecryptStep)
	outputDecFileEntry.grid(row=0, column=1, columnspan=7, sticky="WE", pady=3)

	outputDecBtn = Button(DecryptStep, text="Browse ...", command=openfileDec)
	outputDecBtn.grid(row=0, column=8, sticky='W', padx=5, pady=2)
	outputDecDir = Label(DecryptStep, text="Save File to:")
	outputDecDir.grid(row=1, column=0, sticky='E', padx=5, pady=2)

	outputDecDirEntry = Entry(DecryptStep)
	outputDecDirEntry.grid(row=1, column=1, columnspan=7, sticky="WE", pady=2)

	outputDecDirBtn = Button(DecryptStep, text="Browse ...", command=opendirectoryDec)
	outputDecDirBtn.grid(row=1, column=8, sticky='W', padx=5, pady=2)
	publicKeyOfSender = Label(DecryptStep, text="Public-Key of sender:")
	publicKeyOfSender.grid(row=2, column=0, sticky='E', padx=5, pady=2)

	publicKeyOfSenderEntry = Entry(DecryptStep)
	publicKeyOfSenderEntry.grid(row=2, column=1, sticky='E', pady=2)
	privateKeyOfReciever = Label(DecryptStep, text="Private-Key of reciever:")
	privateKeyOfReciever.grid(row=2, column=5, padx=5, pady=2)

	privateKeyOfRecieverEntry = Entry(DecryptStep)
	privateKeyOfRecieverEntry.grid(row=2, column=7, pady=2)
	DecryptBTN = tkinter.Button(DecryptStep, text="Decrypt   ", command=decryptor)
	DecryptBTN.grid(row=2, column=8, sticky='W', padx=5, pady=2)

	intro = Label(Aboutus, text="\nA secure file transfer system")
	intro.grid(row=0)
	text1 = Label(Aboutus, text="\nIt enables its users to securely\ntransfer files in 'txt' format without\nany third party eavesdropping\n")
	text1.grid(row=1)
	githublink = Label(Aboutus, text="Know More", fg="blue", cursor="hand2")
	githublink.bind("<Button-1>", opengithub)
	githublink.grid(row=2)

	form.mainloop()


if __name__ == "__main__":
	main()
