## Gerando um par de chaves com keytool

### Gerando um arquivo JKS com um par de chaves
keytool -genkeypair -alias oauth2 -keyalg RSA -keypass 123456 -keystore oauth2.jks -storepass 123456 -validity 3650

### Listando as entradas de um arquivo JKS
keytool -list -keystore oauth2.jks



## Extraindo a chave pública no formato PEM

### Gerando o certificado

keytool -export -rfc -alias oauth2 -keystore oauth2.jks -file oauth2-cert.pem

### Gerando a chave pública

openssl x509 -pubkey -noout -in oauth2-cert.pem > oauth2-pkey.pem



## Extraindo a chave privada no formato PEM

### Convertendo o arquivo JKS para formato PKCS12

keytool -importkeystore -srckeystore oauth2.jks -srcstorepass 123456 -srckeypass 123456 -srcalias oauth2 -destalias oauth2 -destkeystore oauth2.p12 -deststoretype PKCS12 -deststorepass 123456 -destkeypass 123456

### Exportando private key do arquivo PKCS12 gerado

openssl pkcs12 -in oauth2.p12 -nodes -nocerts -out private_key.pem



## Multi-Factor Authentication reference
https://sultanov.dev/blog/multi-factor-authentication-with-spring-boot-and-oauth2/#:~:text=Multi%2Dfactor%20Authentication%20(MFA),the%20likelihood%20of%20unauthorized%20access.
