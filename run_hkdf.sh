#!/bin/bash
hello_hash=$1
shared_secret=$2
zero_key=0000000000000000000000000000000000000000000000000000000000000000
early_secret=$(./hkdf extract 00 $zero_key)
empty_hash=$(openssl sha256 < /dev/null | sed -e 's/.* //')
derived_secret=$(./hkdf expandlabel $early_secret "derived" $empty_hash 32)
handshake_secret=$(./hkdf extract $derived_secret $shared_secret)
csecret=$(./hkdf expandlabel $handshake_secret "c hs traffic" $hello_hash 32)
ssecret=$(./hkdf expandlabel $handshake_secret "s hs traffic" $hello_hash 32)
client_handshake_key=$(./hkdf expandlabel $csecret "key" "" 16)
server_handshake_key=$(./hkdf expandlabel $ssecret "key" "" 16)
client_handshake_iv=$(./hkdf expandlabel $csecret "iv" "" 12)
server_handshake_iv=$(./hkdf expandlabel $ssecret "iv" "" 12)
echo plop $client_handshake_key $server_handshake_key $client_handshake_iv $server_handshake_iv plop

