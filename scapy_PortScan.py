#!/usr/share/python

from scapy.all import *

import sys

conf.verb = 0


if ((len(sys.argv) != 2)):
	print ("------------------------------------------------------------")
	print ("Code por Guilherme Martins Vicente")
	print ("------------------------------------------------------------")
	print ("Modo de uso: python3 script.py IP")
	print ("------------------------------------------------------------")
else:

	portas = [80,22,23,445,443,8080,2222]

	pIP = IP(dst=sys.argv[1])
	pTCP = TCP(dport=portas, flags="S")
	meuPacote = pIP/pTCP
	resp, noresp = sr(meuPacote)

	for scan in resp:
		portass = scan[1][TCP].sport
		flag = scan[1][TCP].flags

		if (flag == "SA"):
			print (f"Porta: {portass} -> Aberta | Flag: {flag}")
