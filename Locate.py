#!/usr/bin/python
# coding: utf-8

import argparse
from Registry import Registry

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

# Argparse
Parser = argparse.ArgumentParser()
Parser.add_argument("--file","-f",help="Supply the hive file",type=str,action="store")
Parser.add_argument("--persist_S","-ps",help="Use this to scan for persistence",action="store_true",default=False)
Parser.add_argument("--filetype","-ft",help="Enter either 'hive' or 'reg' based of filetype",type=str,action="store")
Parser.add_argument("--output","-o",help="Enter file to output to",type=str,default="",action="store")
Parser.add_argument("--verbose","-v",help="Use for debugging",action="store_true",default=0)
Args = Parser.parse_args()

class RegHandler():
	def __init__(self,Scan,File,FileType,Output,Verbose):
		self.Scan = Scan 
		self.File = File
		self.FileType = FileType
		self.Results = {}
		self.OutputFile = Output
		self.tab = "    "
		self.Verbose = Verbose
		self.PersistenceLocations = {"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute",
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
									"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
									"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
									"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\load"}

	def scan(self):
		if self.FileType.lower() == "reg": self.RegScan()
		else : self.HiveScan()


	def RegScan(self):
		if self.Scan:

			reg = Registry.Registry(self.File)

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
			self.OutputResults()

		else:
			return()

	def HiveScan(self):
		print("I Do Nothing")

	def OutputResults(self):
		for Name in self.PersistenceLocations:
			try:
				if self.Results[Name]:
					Notify.Success(f"{Name} Yielded {len(self.Results[Name])} results")
					tmp = self.Results[Name]
					for _ in tmp:
						print(f"{self.tab}{_}")
				else:
					continue
			except KeyError:
				pass



# Registry Handling 

#! Add Some Checking for Correct Args E.g Filetype 

R = RegHandler(Args.persist_S,Args.file,Args.filetype,Args.output,Args.verbose)
R.scan()


