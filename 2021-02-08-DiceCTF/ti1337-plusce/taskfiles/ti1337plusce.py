#!/usr/bin/env python3

from pathlib import Path
import subprocess
import sys
import os
import colr

ppp = print
print = lambda s: __builtins__.print(colr.Colr(s).rainbow(freq=0.8))
input = lambda s: (__builtins__.print(colr.Colr(s).rainbow(freq=0.8), end=""), __builtins__.input())[1]

print("Welcome to the TI-1337 Plus CE!")
username = input("Enter your username: ")
userdir = Path(username).resolve()
print("[D] len(username)=%s, Path.cwd()=%s, userdir.parents=%s" % (len(username), Path.cwd(), list(userdir.parents)))
if len(username) < 16 or len(set(username)) < 8 or Path.cwd() not in userdir.parents:
	print("Invalid username.")
	sys.exit()
userdir.mkdir(exist_ok=True)
os.chdir(userdir)

print("1. Start new session")
print("2. Restore session")
opt = input("What would you like to do? ")

name = input("Session name: ")
session = Path(name).resolve()

print('[D] session.parents=%s' % session.parents)
if Path.cwd() not in session.parents:
	print("Invalid session name.")
	sys.exit()
if opt == "1":
	if session.exists():
		print("Session already exists.")
		sys.exit()
	code = ""
elif opt == "2":
	try:
		with session.open() as f:
			code = f.read()
	except FileNotFoundError:
		print("Session not found.")
		sys.exit()
else:
	print("Invalid option.")
	sys.exit()

print("You can use variables and math operations. Results of expressions will be outputted.")
print("Enter your calculations: ")
if code: print("> "+code.strip().replace("\n", "\n> "))
line = input("> ")
while line:
	code += line + "\n"
	line = input("> ")
with open(name, "w") as f:
	f.write(code)

try: out = subprocess.check_output(["/run/cpython/python", "-S", "-i"], input=code.encode("utf-8"), stderr=subprocess.STDOUT, timeout=1)
except subprocess.CalledProcessError as e: ppp(e.output.decode() + '\nThis is not math!')
else: print(out.decode("utf-8").strip())
