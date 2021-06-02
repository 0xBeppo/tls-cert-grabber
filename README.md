# TLS Certificate Grabber

En este repositorio podemos encontrar dos scripts capaces de obtener el certificado TLS del dispositivo indicado, en sus versiones python, mediante scapy, y PHP, mediante su servicio cURL.

## Versión PHP

Esta es una simple prueba de concepto de como mediante PHP y el servicio cURL somos capaces de obtener el certificado del dispositivo indicado. Al ser esto una POC, la ip del dispositivo está hardcodeada en la variable `$url`, y el certificado lo obtendremos en un fichero llamado _dump_ en el propio directorio.

## Versión Python

Esté script en python tiene la misma funcíon anteriormente comentada, pero para ello usando paquetes "_client-hello_" manualmente crafteados mediante scapy, para luego poder loggear la información del dispositivo "nombre y organización" con el objetivo de realizar un posterior fingerprinting con estos datos.

Para utilizar la version python, es necesario instalar las dependencias del fichero requirements.txt mediante el comando `pip install requirements.txt`
