from flask import Flask, render_template, request, send_from_directory
from process_cert import process_certificate, auto_service
import os

app = Flask(__name__)
app.config["DEBUG"] = True


@app.route("/", methods=["GET", "POST"])
def hello():
    return render_template("input_form2.html")


@app.route("/request", methods=["POST"])
def cert_request():
    error = ""
    gen_only = False
    dl_only = False
    force_gen = False
    desc = request.form["certname"]
    st = request.form["state"]
    if request.form["actions"] == "gen_only":
        gen_only = True
    elif request.form["actions"] == "dl_only":
        dl_only = True
    host = request.form["host"]
    certsrv = request.form["certserver"]
    if desc == "":
        error += "Por favor, entre com um nome de certificado válido."
        return render_template("input_form2.html", error=error)
    if "force" in request.form:
        force_gen = True
    try:
        result = process_certificate(
            download_only=dl_only,
            generate_only=gen_only,
            state=st,
            description=desc,
            host=host,
            force=force_gen,
            certserver=certsrv,
            base_path=app.root_path,
        )
    except Exception as err:
        for i in err.args:
            if isinstance(i, str):
                error += i + "\n"
        return render_template("input_form2.html", error=error)
    return render_template(
        "certificate.html",
        client_win10=result["client_export"]["win10"],
        client_linux=result["client_export"]["linux"],
        client_macos=result["client_export"]["macos"],
    )


@app.route("/client/<path:filename>", methods=["GET"])
def download(filename):
    client_dir = os.path.join(app.root_path, "client/")
    return send_from_directory(directory=client_dir, filename=filename)


@app.route("/autoservice", methods=["GET"])
def get_self_certificate():
    username = request.environ["REMOTE_USER"].split("@")[0]
    cert_link = auto_service(username, app.root_path)
    return render_template(
        "autoservice.html", nuvem_url=cert_link["url"], nuvem_pw=cert_link["password"]
    )


@app.route("/api/autoservice", methods=["GET"])
def api_autoservice():
    username = request.environ["REMOTE_USER"].split("@")[0]
    cert_link = auto_service(username, app.root_path)
    return cert_link
