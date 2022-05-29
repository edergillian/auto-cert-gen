import sys
import auto_cert_gen


def process_certificate(
    description,
    download_only=False,
    host="<PFSENSE_HOSTNAME>",
    generate_only=False,
    force=False,
    base_path="",
):

    result = {}
    username = "<AD_USERNAME>"
    password = "<AD_PASSWORD>"

    vpnapi = auto_cert_gen.connect_pfsense(host)

    # Baixa section 'certs' da config do VPN2
    print("Downloading pfSense Certificate and OpenVPN configuration...")
    certs = vpnapi.config_get(section="cert")
    openvpn_servers = vpnapi.config_get(section="openvpn")

    # Procura referencia de certificado CA para servidor    OpenVPN    de usuarios externos
    # Tambem aproveita e calcula o ID do servidor OpenVPN
    print("Extracting OpenVPN server ID and CA reference...")
    for i in range(len(openvpn_servers["openvpn-server"])):
        if openvpn_servers["openvpn-server"][i]["local_port"] == "1194":
            caref = openvpn_servers["openvpn-server"][i]["caref"]
            srvid = openvpn_servers["openvpn-server"][i]["vpnid"]

    if (
        auto_cert_gen.check_cert_exists(certs, description)
        and not force
        and not download_only
    ):
        raise Exception(
            "O certificado %s já existe no pfSense. Selecione a opção 'Apenas baixar cliente' para fazer o download do instalador ou marque 'Força geração de certificado' para substituir o certificado já existente."
            % (description)
        )

    # Gera certificado
    if not download_only:
        try:
            cert_result = auto_cert_gen.cert_save_pfsense(
                vpnapi, description, username, password, caref, certs
            )
        except:
            raise Exception("Problemas ao gerar certificado: " + cert_result)
        result["generate"] = cert_result

    if not generate_only:
        try:
            client_export = auto_cert_gen.client_export_pfsense(
                vpnapi, srvid, certs, description, host, base_path,
            )
        except:
            raise Exception("Problemas ao exportar clientes.")
        result["client_export"] = client_export

    return result


def auto_service(user, base_path):
    host = "<PFSENSE_HOSTNAME>"
    username = "<PFSENSE_USERNAME>"
    password = "<PFSENSE_PASSWORD>"
    vpnapi = auto_cert_gen.connect_pfsense(host)

    # Baixa section 'certs' da config do VPN2
    print("Downloading pfSense Certificate and OpenVPN configuration...")
    certs = vpnapi.config_get(section="cert")
    openvpn_servers = vpnapi.config_get(section="openvpn")

    # Procura referencia de certificado CA para servidor    OpenVPN    de usuarios externos
    # Tambem aproveita e calcula o ID do servidor OpenVPN
    print("Extracting OpenVPN server ID and CA reference...")
    for i in range(len(openvpn_servers["openvpn-server"])):
        if openvpn_servers["openvpn-server"][i]["local_port"] == "1194":
            caref = openvpn_servers["openvpn-server"][i]["caref"]
            srvid = openvpn_servers["openvpn-server"][i]["vpnid"]

    if not auto_cert_gen.check_cert_exists(certs, user):
        try:
            auto_cert_gen.cert_save_pfsense(
                vpnapi, user, username, password, caref, certs
            )
        except:
            return "Erro ao gerar certificado"

    try:
        client_export = auto_cert_gen.client_export_pfsense(
            vpnapi, srvid, certs, user, host, base_path,
        )
    except:
        return "Erro ao exportar cliente"

    share_url = auto_cert_gen.share_nuvem(base_path, client_export, user)

    return share_url
