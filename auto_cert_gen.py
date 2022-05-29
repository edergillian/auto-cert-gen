#!/usr/bin/env python3
import os, sys, json, base64, requests, paramiko, scp, subprocess, argparse, string, random
from time import time
from PfsenseFauxapi.PfsenseFauxapi import PfsenseFauxapi, PfsenseFauxapiException
from requests_ntlm import HttpNtlmAuth
from paramiko import AutoAddPolicy
import xml.etree.ElementTree as ET


def submit_csr(certname, user, pw, state="BSB"):
    print("Creating CSR for CN={}".format(certname) + "...")
    error = ""
    certattrib = "CertificateTemplate:<CERT_TEMPLATE_NAME>"
    if state == "BSB":
        subj_city_state = "L=<CITY1>/ST=<STATE1>"
    else:
        subj_city_state = "L=<CITY2>/ST=<STATE2>"

    subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-nodes",
            "-out",
            "/tmp/" + certname + ".pem",
            "-keyout",
            "/tmp/" + certname + ".key",
            "-subj",
            "/emailAddress=<ADMIN_MAIL>/OU=<OU_NAME>/O=<ORG_NAME>/"
            + subj_city_state
            + "/C=<COUNTRY_CODE>/CN="
            + certname,
        ]
    )
    print("Sending CSR request to certificate server...")
    with open("/tmp/" + certname + ".pem", "r") as file:
        csrfile = file.read()

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Host": "<CA_HOSTNAME>",
        "Referer": "http://<CA_HOSTNAME>/certsrv/certrqxt.asp",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    data = {
        "Mode": "newreq",
        "CertRequest": csrfile,
        "CertAttrib": certattrib,
        "TargetStoreFlags": "0",
        "SaveCert": "yes",
        "ThumbPrint": "",
    }

    response = requests.post(
        "http://<CA_HOSTNAME>/certsrv/certfnsh.asp",
        headers=headers,
        data=data,
        verify=False,
        auth=HttpNtlmAuth(user, pw),
    )

    lines = response.text.splitlines()

    for i in range(len(lines)):
        if lines[i].find("function handleGetCert() {") >= 0:
            certlocation = lines[i + 1].split('"')[1]

    try:
        certlink = "http://<CA_HOSTNAME>/certsrv/" + certlocation
    except NameError:
        for i in lines:
            if i.find("invalid credentials") >= 0:
                error += "Usuário e/ou senha incorretos."
            elif i.find("Denied by Policy") >= 0:
                error += "Este usuário não pode emitir esse tipo de certificado."
        raise Exception(error)

    print("Downloading certificate from certificate server")
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Host": "<CA_HOSTNAME>",
        "Referer": "http://<CA_HOSTNAME>/certsrv/certrqxt.asp",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    try:
        certificate = requests.get(
            certlink, headers=headers, verify=False, auth=HttpNtlmAuth(user, pw)
        )
    except:
        raise Exception("Erro ao baixar o certificado.")

    return certificate


def cert_save_pfsense(pfsenseapi, certname, user, pw, caref, certs):
    print("Saving certificate {} to pfSense".format(certname))
    crt = submit_csr(certname, user, pw)
    # Le chave privada
    key = open("/tmp/" + certname + ".key", "r")
    # Converte certificado e chave para base64
    crt64 = base64.b64encode(crt.text.encode("ascii")).decode("ascii")
    key64 = base64.b64encode(key.read().encode("ascii")).decode("ascii")

    # Gera random hexadecimal de 13 digitos a partir da hora, simula function uniqid() do PHP.  Serve como identificador unico do certificado no pfSense
    refid = hex(int(time() * 10000000))[3:]

    # Verifica se o refid gerado existe; caso exista, gera novo
    while True:
        refid_exists = False
        for i in certs:
            if i["refid"] == refid:
                print("Certificate reference ID already in use; generating a new one")
                refid_exists = True
                break
        if refid_exists == False:
            break
        refid = hex(int(time() * 10000000))[3:]

    # Inclui novo certificado na variavel que contem section certs;
    certs.append(
        {"refid": refid, "descr": certname, "crt": crt64, "prv": key64, "caref": caref,}
    )

    # Salva nova config no pfSense
    result = pfsenseapi.config_set(certs, "cert")

    return (
        "Certificado salvo! Se for preciso reverter para um backup, use este arquivo: "
        + result["data"]["previous_config_file"]
    )


def connect_pfsense(host):
    error = ""
    # Conecta com VPN2 pela Faux API
    print("Connecting to pfSense in {}...".format(host))
    try:
        pfsenseapi = PfsenseFauxapi(
            host,
            "<PFSENSE_FAUXAPI_ACCESS_KEY>",
            "<PFSENSE_FAUXAPI_SECRET_KEY>",
        )
    except requests.exceptions.ConnectionError:
        raise Exception("Host pfSense inexistente ou sem conectividade.")

    # Testa conexao com pfSense
    try:
        pfsenseapi.config_get("aliases")
    except PfsenseFauxapiException as e:
        error += (
            "Problema de acesso à API do pfSense. Por favor, verifique as credenciais de acesso da FauxAPI e/ou as funções permitidas. Erro: "
            + e
        )
        raise Exception(error)

    print("Connection successul!")
    return pfsenseapi


def check_cert_exists(certificates, description):
    print("Checking if certificate {} exists in pfSense".format(description))
    cert_exists = False

    for c in certificates:
        if c["descr"] == description:
            cert_exists = True

    return cert_exists


def client_export_pfsense(pfsenseapi, serverid, certs, description, host, base_path):
    print("Exporting client installer for {}".format(description))
    error = ""
    # Calcula o ID do usuario para geracao do client export
    for i in range(len(certs)):
        if certs[i]["descr"] == description:
            crtid = i
            # id = certs[i]

    try:
        crtid
    except NameError:
        error += "Certificado {} não existe.".format(description)
        raise Exception(error)

    usrid = ""
    useaddr = "serverhostname"
    verifyservercn = "auto"
    blockoutsidedns = 0
    legacy = 0
    randomlocalport = 1
    usetoken = 0
    password = ""
    proxy = 0
    advancedoptions = ""
    usepkcs11 = 0
    openvpn_version = "Win10"
    pkcs11providers = ""
    pkcs11id = ""
    nokeys = "false"
    expformat_linux = "zip"
    expformat_macos = "inlinevisc"
    skiptls = "false"
    doslines = "false"

    dados_win10 = {
        "function": "openvpn_client_export_installer",
        "args": [
            serverid,
            usrid,
            crtid,
            useaddr,
            verifyservercn,
            blockoutsidedns,
            legacy,
            randomlocalport,
            usetoken,
            password,
            proxy,
            advancedoptions,
            openvpn_version,
            usepkcs11,
            pkcs11providers,
            pkcs11id,
        ],
    }

    dados_linux = {
        "function": "openvpn_client_export_config",
        "args": [
            serverid,
            usrid,
            crtid,
            useaddr,
            verifyservercn,
            blockoutsidedns,
            legacy,
            randomlocalport,
            usetoken,
            nokeys,
            proxy,
            expformat_linux,
            password,
            skiptls,
            doslines,
            advancedoptions,
            usepkcs11,
            pkcs11providers,
            pkcs11id,
        ],
    }

    dados_macos = {
        "function": "openvpn_client_export_config",
        "args": [
            serverid,
            usrid,
            crtid,
            useaddr,
            verifyservercn,
            blockoutsidedns,
            legacy,
            randomlocalport,
            usetoken,
            nokeys,
            proxy,
            expformat_macos,
            password,
            skiptls,
            doslines,
            advancedoptions,
            usepkcs11,
            pkcs11providers,
            pkcs11id,
        ],
    }

    # Baixa instaladores Win10 e Linux
    installer_win10 = pfsenseapi.function_call(dados_win10)
    config_linux = pfsenseapi.function_call(dados_linux)

    file_path = installer_win10["data"]["return"]
    local_path = base_path + "/client/openvpn-{}-win10.exe".format(description)
    local_rel_path = "client/openvpn-{}-win10.exe".format(description)
    file_path_linux = config_linux["data"]["return"]
    local_path_linux = base_path + "/client/openvpn-{}-config-linux.zip".format(
        description
    )
    local_rel_path_linux = "client/openvpn-{}-config-linux.zip".format(description)

    key_file = base_path + "/autogen.key"
    ssh_client = paramiko.SSHClient()
    ssh_client.load_system_host_keys()
    ssh_client.set_missing_host_key_policy(AutoAddPolicy())
    ssh_client.connect(
        host,
        username="autogen",
        key_filename=key_file,
        look_for_keys=True,
        timeout=5000,
    )
    scp_client = scp.SCPClient(ssh_client.get_transport())
    scp_client.get(file_path, local_path)
    scp_client.get(file_path_linux, local_path_linux)

    # Remove arquivo temporario do instalador no pfSense
    del_temp_file = {
        "function": "unlink_if_exists",
        "args": [file_path],
    }
    deleted = pfsenseapi.function_call(del_temp_file)

    if not deleted["data"]["return"]:
        error += (
            "Houve um problema ao remover o arquivo temporário %s. Ele deve ser removido manualmente no host pfSense."
            % (file_path)
        )
        raise Exception(error)

    # Baixa config MacOS
    config_macos = pfsenseapi.function_call(dados_macos)
    g = open(
        base_path + "/client/openvpn-{}-config-macos.ovpn".format(description), "a"
    )
    g.write(config_macos["data"]["return"])
    g.close()

    result = {
        "win10": local_rel_path,
        "linux": local_rel_path_linux,
        "macos": "client/openvpn-{}-config-macos.ovpn".format(description),
    }

    return result


def share_nuvem(base_path, client_files, description):
    # Upload de arquivo
    user = "<OWNCLOUD_USERNAME>"
    pw = "<OWNCLOUD_PASSWORD>"

    response = requests.request(
        "MKCOL",
        "https://<OWNCLOUD_HOSTNAME>/remote.php/webdav/" + description,
        auth=(user, pw),
    )

    for i in client_files:
        from_file = client_files[i]
        data = open(base_path + "/" + from_file, "rb").read()
        response = requests.put(
            "https://<OWNCLOUD_HOSTNAME>/remote.php/webdav/"
            + description
            + "/"
            + from_file.split("/")[1],
            data=data,
            auth=(user, pw),
        )

    # Cria link protegido por senha
    random_pw = "".join(
        random.SystemRandom().choice(string.ascii_uppercase + string.digits)
        for _ in range(30)
    )
    data = {
        "path": description,
        "shareType": "3",
        "password": random_pw,
        "permissions": "1",
    }
    response = requests.post(
        "https://<OWNCLOUD_HOSTNAME>/ocs/v1.php/apps/files_sharing/api/v1/shares",
        data=data,
        auth=(user, pw),
    )

    result = {}

    if response.status_code == 200:
        root = ET.fromstring(response.text)
        for i in root.iter("url"):
            result = {"url": i.text, "password": random_pw}
    else:
        raise Exception("Não foi possível criar share na Nuvem Owncloud")

    return result
