#!/usr/bin/python
# coding: utf-8

import argparse
from Registry import Registry
from contextlib import redirect_stdout, redirect_stderr	

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

	def Warning(Message):
		'Red Output Message'	
		print(f"{Color.ErrorColor}[!!] - {Message}{Color.RESET}")

# Argparse
Parser = argparse.ArgumentParser(description=f"{Color.InfoColor}Use the Following Arguments{Color.RESET}")
Parser.add_argument("file",help="Supply the hive file",type=str,action="store")
Parser.add_argument("--persist_S","-ps",help="Use this to scan for persistence",action="store_true",default=False)
Parser.add_argument("--mru","-M",help="Use to scan the MRU List",action="store_true",default=False)
Parser.add_argument("--silent","-s",help="Enter file to output to",default=False,action="store_true")
Parser.add_argument("--verbose","-v",help="Use for debugging",action="store_true",default=0)
Parser.add_argument("--force","-F",help="Force the use of a hivetype X when inputted",action="store",metavar="",default="",type=str)

Args = Parser.parse_args()

class RegHandler():
	def __init__(self,Args):
		# Unpacking Args
		self.PerScan = Args.persist_S 
		self.MRU_Scan = Args.mru
		self.File = Args.file 
		self.Silent = Args.silent
		self.Verbose = Args.verbose
		self.ForceHive = Args.force.upper()

		# Setting Variables
		self.tab = "    "
		self.Results = {}

		self.Keys = ["HKU","HKLM","HKCU","HKCR"] # Ignoring HKCC 
		self.KeyLikelyhood = {"HKU":0, "HKLM":0, "HKCU":0, "HKCR":0}
		self.HiveType = ""
		self.reg = Registry.Registry(self.File)

		#* Running Extra Init Functions
		self.Persistence()
		self.MostRecentlyUsed()

	def MostRecentlyUsed(self):
		self.MRU_Locations = ["Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU",
					"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU",
					"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
					"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
					"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
					"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management"]
					


	def Persistence(self):
		self.PersistenceLocations = None

		self.HKCU_Persistence = ["Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce" 
								"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices", 
								"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell", 
								"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
								"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 
								"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", 
								"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\load"]

		self.HKLM_Persistence = ["SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute", 
							 	"System\\CurrentControlSet\\Services", 
								"System\\CurrentControlSet\\Services", 
								"Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
								"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
								"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", 
								"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
								"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
								"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad", 
								"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
								"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx", 
								"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
								"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", 
								"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
								"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler",
								"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",]



	def Initiate(self):
		'Run to Initate Scanning'
		if not self.ForceHive:
			self.HiveID()
		else:
			if self.ForceHive not in self.Keys:
				Notify.Error("Key Not of Valid Type") ; return()
			self.HiveType = self.ForceHive
			Notify.Warning(f"Forcing HiveType : {self.HiveType}")

		self.ScanManager()
		self.OutputManager()

	def ScanManager(self):
		'Manages What Scans are run' 
		if self.PerScan: self.RegScan()

		if self.MRU_Scan: self.MRUScan()


	def MRUScan(self):
		'Scans MRU Hives'
		print("\n-- Scanning MRU Hives --\n")

		reg = self.reg 
		Scan_Results = {}
		if self.HiveType != "HKCU":
			Notify.Failure("Only HKCU Hives Can be Scanned for MRU")
			return()
		else:
			for Location in self.MRU_Locations:
				try: 
					key = reg.open(Location)
					KeyResults = []

					for value in [v for v in key.values() if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:
						KeyResults.append(f" {value.name()} -> '{value.value()}'")

					Scan_Results.update({Location : KeyResults})
				except Registry.RegistryKeyNotFoundException:
					if self.Verbose:
						Notify.Failure(f"Key {Location} not found")
				except Exception as Exc:
					Notify.Error(f"Encountered '{Exc}'")

		self.Results.update({"MRUScan" : Scan_Results})

	def RegScan(self):
		'Scans Registry Files'
		print("\n-- Scanning Registry --\n")
		
		reg = self.reg
		Scan_Results = {}
		if self.HiveType == "HKCU" : self.PersistenceLocations = self.HKCU_Persistence
		elif self.HiveType == "HKLM" : self.PersistenceLocations = self.HKLM_Persistence

		if self.PersistenceLocations:
			for Location in self.PersistenceLocations:
				try:
					key = reg.open(Location)
					KeyResults = []

					for value in [v for v in key.values() if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:
						KeyResults.append(f" {value.name()} -> '{value.value()}'")

					Scan_Results.update({ Location : KeyResults})
				except Registry.RegistryKeyNotFoundException:
					if self.Verbose:
						Notify.Failure(f"Key {Location} not found")
				except Exception as Exc:
					Notify.Error(f"Encountered '{Exc}'")
			self.Results.update({"RegScan" : Scan_Results})

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
				Notify.Success(f"Predicted {key} with {Probability} Generic Values")
			else:
				Notify.Failure(f"{key} with {self.KeyLikelyhood.get(key)} Generic Values")
		
		self.HiveType = Prediction

	def OutputManager(self):
		if self.Silent:
			with open(f"{self.File}-{self.HiveType}.scan","w") as f:
				with redirect_stdout(f):
					with redirect_stderr(f):
						self.OutputResults()
		else:
			self.OutputResults()

	def OutputResults(self):
		for Value in ["RegScan","MRUScan"]:
			CategoryOutput = self.Results.get(Value)
			if Value == "RegScan":
				Locations = self.PersistenceLocations
			if Value == "MRUScan":
				Locations = self.MRU_Locations
			if Locations == None: continue
			for Name in Locations:
				try:
					if CategoryOutput == None: continue
					if CategoryOutput[Name]:
						Notify.Success(f"{Name} Yielded {len(CategoryOutput[Name])} results")
						tmp = CategoryOutput[Name]
						for _ in tmp:
							print(f"{self.tab}{_}")
						print("")
					else:
						continue
				except KeyError:
					pass
	 
if (not Args.mru and not Args.persist_S):
	Notify.Error("You must choose a scan type")
R = RegHandler(Args)
R.Initiate()


