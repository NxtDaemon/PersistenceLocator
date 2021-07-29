# PersistenceLocator

Persistence locator takes advantage of the python-registry PyPi package to access hive files and access predetermined locations upon 
running the program it will perform a incredibly janky fingerprinting method to identify what hive it is looking at ( Currently only HKLM and HKCU work) 
I doubt I will be adding any support for HKU and HKCC as they dont have any persistence methods which I know of. Once fingerprinting is complete based on this 
it will assume the hive and run persistence enumeration against it, additionally it can run MRU enumeration if enabled on command-line, in foresight to if fingerprinting does become too unstable you can use the `-F` parameter to force it to take the Hive Value. additionally you can use the -s parameter to redirect output but given that you're using bash or a similar shell just redirect with `>` 
