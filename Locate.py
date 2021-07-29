#!/usr/bin/python
# coding: utf-8

import argparse
from Registry import Registry
from contextlib import redirect_stdout

# Written By NxtDaemon Any Issues or Additions you would like please contact me here https://nxtdaemon.xyz/contact
# |  \  |  \          |  \   |       \                                                  
# | ▓▓\ | ▓▓__    __ _| ▓▓_  | ▓▓▓▓▓▓▓\ ______   ______  ______ ____   ______  _______  
# | ▓▓▓\| ▓▓  \  /  \   ▓▓ \ | ▓▓  | ▓▓|      \ /      \|      \    \ /      \|       \ 
# | ▓▓▓▓\ ▓▓\▓▓\/  ▓▓\▓▓▓▓▓▓ | ▓▓  | ▓▓ \▓▓▓▓▓▓\  ▓▓▓▓▓▓\ ▓▓▓▓▓▓\▓▓▓▓\  ▓▓▓▓▓▓\ ▓▓▓▓▓▓▓\
# | ▓▓\▓▓ ▓▓ >▓▓  ▓▓  | ▓▓ __| ▓▓  | ▓▓/      ▓▓ ▓▓    ▓▓ ▓▓ | ▓▓ | ▓▓ ▓▓  | ▓▓ ▓▓  | ▓▓
# | ▓▓ \▓▓▓▓/  ▓▓▓▓\  | ▓▓|  \ ▓▓__/ ▓▓  ▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓ ▓▓ | ▓▓ | ▓▓ ▓▓__/ ▓▓ ▓▓  | ▓▓
# | ▓▓  \▓▓▓  ▓▓ \▓▓\  \▓▓  ▓▓ ▓▓    ▓▓\▓▓    ▓▓\▓▓     \ ▓▓ | ▓▓ | ▓▓\▓▓    ▓▓ ▓▓  | ▓▓ 
#  \▓▓   \▓▓\▓▓   \▓▓   \▓▓▓▓ \▓▓▓▓▓▓▓  \▓▓▓▓▓▓▓ \▓▓▓▓▓▓▓\▓▓  \▓▓  \▓▓ \▓▓▓▓▓▓ \▓▓   \▓▓
#  __    __            __     _______                                                   

class Color:
    'Class for Colors to be used in Execution'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    NumColor = DARKCYAN
    QuestionColor = BOLD+YELLOW
    ErrorColor = RED+BOLD
    InfoColor = CYAN 
    SuccessColor = GREEN
    InputColor = GREEN+BOLD

class Notify():
	'Managed what type of message is sent'

	def Error(Message):
		'Error Messages'
		print(f"{Color.ErrorColor}[!] - {Message}{Color.RESET}")

	def Info(Message):
		'Infomation Messages'
		print(f"{Color.InfoColor}[*] - {Message}{Color.RESET}")

	def Success(Message):
		'Success Messages'
		print(f"{Color.SuccessColor}[+] - {Message}{Color.RESET}")

	def Question(Message):
		'Get infomation from user'
		return(input(f"{Color.QuestionColor}[?] - {Message}{Color.RESET}\n{Color.InputColor}>{Color.RESET}"))

	def Failure(Message):
		'Red Output Message'
		print(f"{Color.ErrorColor}[-] - {Message}{Color.RESET}")

# Argparse
Parser = argparse.ArgumentParser(description=f"{Color.InfoColor}Use the Following Arguments{Color.RESET}")
Parser.add_argument("file",help="Supply the hive file",type=str,action="store")
Parser.add_argument("--persist_S","-ps",help="Use this to scan for persistence",action="store_true",default=False)
Parser.add_argument("--mru","-M",help="Use to scan the MRU List of the Hive or Reg file",action="store_true",default=False)

Parser.add_argument("--silent","-s",help="Enter file to output to",default=False,action="store_true")
Parser.add_argument("--verbose","-v",help="Use for debugging",action="store_true",default=0)


Args = Parser.parse_args()

class RegHandler():
	def __init__(self,Args):
		# Unpacking Args
		self.PerScan = Args.persist_S 
		self.MRU_Scan = Args.mru
		self.File = Args.file 
		self.Silent = Args.silent
		self.Verbose = Args.verbose

		# Setting Variables
		self.tab = "    "
		self.Results = {}
		self.PersistenceLocations = None

		self.HKCU_Persistence = ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce" 
								"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices", 
								"HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell", 
								"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
								"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 
								"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", 
								"HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\load"]

		self.HKLM_Persistence = ["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute", 
							 	"HKLM\\System\\CurrentControlSet\\Services", 
								"HKLM\\System\\CurrentControlSet\\Services", 
								"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
								"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
								"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", 
								"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
								"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
								"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad", 
								"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
								"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", 
								"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
								"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", 
								"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
								"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler",
								"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",]

		self.Keys = ["HKU","HKLM","HKCU","HKCR"] # Ignoring HKCC 
		self.KeyLikelyhood = {"HKU":0, "HKLM":0, "HKCU":0, "HKCR":0}
		self.HiveType = ""
		self.reg = Registry.Registry(self.File)

	def Initiate(self):
		'Run to Initate Scanning'
		self.HiveID()
		self.ScanManager()
		self.OutputManager()

	def ScanManager(self):
		'Manages What Scans are run' 
		if self.PerScan: self.RegScan()

		elif self.MRU_Scan:
			print("Not Implemented Yet")

	def RegScan(self):
		'Scans Registry Files'
		print("\n-- Scanning Registry --\n")
		
		reg = self.reg

		if self.HiveType == "HKCU" : self.PersistenceLocations = self.HKCU_Persistence
		elif self.HiveType == "HKLM" : self.PersistenceLocations = self.HKLM_Persistence

		for Location in self.PersistenceLocations:
			try:
				key = reg.open(Location)
				KeyResults = []

				for value in [v for v in key.values() if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:
					KeyResults.append(f" {value.name()} -> '{value.value()}'")

				self.Results.update({ Location : KeyResults})
			except Registry.RegistryKeyNotFoundException:
				if self.Verbose:
					Notify.Error(f"Key {Location} not found")
			except Exception as Exc:
				Notify.Error(f"Encountered '{Exc}'")
			
	def HiveID(self):
		print("\n-- Detecting HiveType --\n")
		# Define Vars 

		HKLM_Standard = ["BCD00000000","COMPONENTS","DRIVERS","HARDWARE","SAM","Schema","SECURITY","SOFTWARE","SYSTEM"]
		HKCU_Standard = ["AppEvents","Console","Control Panel","Environment","EUDC","Identities","Keyboard Layout","Network","Printers","Software","System","Volatile Environment"]
		HKU_Standard = [".DEFAULT","S-1-5-18","S-1-5-19","S-1-5-20","S-1-5-21-0123456789-012345678-0123456789-1004","S-1-5-21-0123456789-012345678-0123456789-1004_Classes"] #* Needs Regex Readjustment to ensure that detection coudl work
		HKCR_Standard = ["nothing"] # use some filetype lib, most start with .xyz and contain info on execution 
	
		reg = self.reg 

		RootKey = reg.root()
		Root_Subkeys = RootKey.subkeys()
		Root_KeyNames = []
		for key in Root_Subkeys:
			Root_KeyNames.append(key.name())
		
		for key in Root_KeyNames:
			if key in HKU_Standard:
				self.KeyLikelyhood["HKU"] += 1 
			elif key in HKCU_Standard:
				self.KeyLikelyhood["HKCU"] += 1 
			elif key in HKU_Standard:
				self.KeyLikelyhood["HKU"] += 1 
			elif key in HKCR_Standard:
				self.KeyLikelyhood["HKCR"] += 1 

		Prediction = max(self.KeyLikelyhood, key=self.KeyLikelyhood.get)
		Probability = self.KeyLikelyhood.get(Prediction) # Maybe Implement Guess %

		for key in self.Keys:
			if key == Prediction:
				Notify.Success(f"Predicted {key} with {Probability}")
			else:
				Notify.Failure(f"{key} with {self.KeyLikelyhood.get(key)}")
		
		self.HiveType = Prediction

	def OutputManager(self):
		if self.Silent:
			with open(f"{self.File}.{self.FileType}scan","w") as f:
				with redirect_stdout(f):
					self.OutputResults()
		else:
			self.OutputResults()

	def OutputResults(self):
		for Name in self.PersistenceLocations:
			try:
				if self.Results[Name]:
					Notify.Success(f"{Name} Yielded {len(self.Results[Name])} results")
					tmp = self.Results[Name]
					for _ in tmp:
						print(f"{self.tab}{_}")
					print("")
				else:
					continue
			except KeyError:
				pass
 

#! Add Some Checking for Correct Args E.g Filetype 

R = RegHandler(Args)
R.Initiate()


