rm ca_key.pem ca_crt.pem server_key.pem server_req.pem server_crt.pem server_ext.cnf client_key.pem client_req.pem client_crt.pem client_ext.cnf

echo subjectAltName = IP:"$1" > server_ext.cnf
# 1. Generate CA's private key and self-signed certificate
openssl req -x509 -newkey rsa:4096 -days 365 -nodes -keyout ca_key.pem -out ca_crt.pem -subj "/C=US"

# 2. Generate web server's private key and certificate signing request (CSR)
openssl req -newkey rsa:4096 -nodes -keyout server_key.pem -out server_req.pem -subj "/CN='$1'"

# 3. Use CA's private key to sign web server's CSR and get back the signed certificate
openssl x509 -req -in server_req.pem -days 100 -CA ca_crt.pem -CAkey ca_key.pem -CAcreateserial -out server_crt.pem -extfile server_ext.cnf

echo subjectAltName = IP:"$1" > client_ext.cnf
# 4. Generate client's private key and certificate signing request (CSR)
openssl req -newkey rsa:4096 -nodes -keyout client_key.pem -out client_req.pem -subj "/CN=*"

# 5. Use CA's private key to sign client's CSR and get back the signed certificate
openssl x509 -req -in client_req.pem -days 100 -CA ca_crt.pem -CAkey ca_key.pem -CAcreateserial -out client_crt.pem -extfile client_ext.cnf
