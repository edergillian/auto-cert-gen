# AutoCertGen

Automatic certificate request & enrollment using OpenSSL and Microsoft AD CS infrastructure, automatic certificate and private key configuration, along with client installer download using pfSense and OpenVPN.

## Usage

```
pip install -r requirements.txt
export FLASK_APP="web_cert_gen.py"
python3 -m flask run --host 0.0.0.0
```

The app needs the pfSense user's private key in the root folder named 'autogen.key' to work properly.

Supported client installers:
- Windows 10
- Linux
- MacOS

The app can also be hosted using Apache2 + mod_wsgi.

## Docker (Legacy)

To run using docker:
```
docker run --rm --volume="$(pwd)/autogen.key:/usr/src/app/autogen.key:ro" --volume="$(pwd)/client:/usr/src/app/client" --name auto-cert-gen <docker_registry>/python/auto-cert-gen:<version> <certifcate_name> <username> <password>
```

## TODO

- Support for other types of client export (installers and configs)