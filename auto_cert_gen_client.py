#!/usr/bin/env python3
import sys
import auto_cert_gen
import argparse


class auto_cert_gen_client:

    name = "AutoCertGenClient"
    args = None
    parser = None

    def __init__(self):
        # Verifica os parametros passados pelo usuario
        self.parser = argparse.ArgumentParser(
            description="Script to generate certificate, register it in pfSense and download exported client."
        )
        self.parser.add_argument("cn", help="certificate name (CN)")
        self.parser.add_argument(
            "-H",
            "--host",
            help="pfSense hostname (default: <PFSENSE_HOSTNAME>)",
            default="<PFSENSE_HOSTNAME>",
        )
        self.parser.add_argument(
            "-c",
            "--certserver",
            help="certificate server for the request",
            default="<CA_HOSTNAME>",
        )
        self.parser.add_argument(
            "-s",
            "--state",
            help="user's State. Default: <STATE1>",
            choices=["<STATE1>", "<STATE2>"],
            default="<STATE2>",
        )
        self.parser.add_argument(
            "--force",
            help="forces certificate generation even if it's in pfSense",
            action="store_true",
        )
        self.parser.add_argument(
            "--pfsense-user",
            help="defines the pfSense username (default: <PFSENSE_USERNAME>)",
            default="<PFSENSE_USERNAME>",
        )
        self.parser.add_argument(
            "--pfsense-private-key-file",
            help="defines the pfSense user's private key filename; the file must be placed in the same folder as the application (default: autogen.key)",
            default="autogen.key",
        )
        group = self.parser.add_mutually_exclusive_group()
        group.add_argument(
            "--generate-only",
            help="only generates the certificate and stores it in pfSense, doesn't download client",
            action="store_true",
        )
        group.add_argument(
            "--download-only",
            help="only downloads client installer/configuration from existing certificate name in pfSense",
            action="store_true",
        )
        self.args = self.parser.parse_args()

    def main(self):
        # Programa principal a partir daqui
        # Configura parametros
        description = self.args.cn
        username = "<AD_USERNAME>"
        password = "<AD_PASSWORD>"

        vpnapi = auto_cert_gen.connect_pfsense(self.args.host)

        # Baixa section 'certs' da config do VPN2
        print("Downloading pfSense Certificate and OpenVPN configuration...")
        certs = vpnapi.config_get(section="cert")
        openvpn_servers = vpnapi.config_get(section="openvpn")

        # Procura referencia de certificado CA para servidor    OpenVPN    de usuarios externos
        # Tambem aproveita e calcula o ID do servidor OpenVPN
        for i in range(len(openvpn_servers["openvpn-server"])):
            if openvpn_servers["openvpn-server"][i]["local_port"] == "1194":
                caref = openvpn_servers["openvpn-server"][i]["caref"]
                srvid = openvpn_servers["openvpn-server"][i]["vpnid"]

        if (
            auto_cert_gen.check_cert_exists(certs, description)
            and not self.args.force
            and not self.args.download_only
        ):
            print(
                "O certificado %s já existe no pfSense. Selecione a opção 'Apenas baixar cliente' para fazer o download do instalador ou marque 'Força geração de certificado' para substituir o certificado já existente."
                % (description)
            )
            sys.exit(1)

        # Gera certificado
        if not self.args.download_only:
            auto_cert_gen.cert_save_pfsense(
                vpnapi, description, username, password, caref, certs
            )

        if not self.args.generate_only:
            auto_cert_gen.client_export_pfsense(
                vpnapi, srvid, certs, description, self.args.host
            )

        sys.exit()


if __name__ == "__main__":
    auto_cert_gen_client().main()
