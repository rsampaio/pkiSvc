openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=US/ST=California/L=San Francisco/CN=ca.rsampaio.info" -keyout ca.key.pem -out ca.cert.pem
