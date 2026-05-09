# About the demo
## Attacker
Simple express server for listening to malicious package
## malicious
For now only postinstall exploit that reads .env files and sends them to the attackers server. Will add runtime exploits (index.js) and other not so trivial exploits soon.
## demo
As of now nothing else than a simulation of a victims package.json infected with our malicious package.

# To test the malicious package:
## Setup attacker's server
1. cd attacker
2. npm install
3. node server.js

## Install suspicious package
1. cd demo/backend
2. npm install (or npm rebuild if running it multiple times)







