#!/bin/bash
#Generating an RSA Key Pair  for sender
openssl genrsa  -out private.pem 2048
#Exporting the public key from the key pair - 
openssl rsa -in private.pem -outform PEM -pubout -out public.pem

#Generating an RSA Key Pair  for receiver
openssl genrsa  -out private_r.pem 2048
#Exporting the public key from the key pair - 
openssl rsa -in private_r.pem -outform PEM -pubout -out public_r.pem