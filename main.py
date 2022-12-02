import base64
import os
import shutil

from flask import Flask, Response, render_template, request
from werkzeug.utils import secure_filename

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/upload", methods=["POST"])
def upload():
    if request.method == "POST":
        f = request.files["file"]
        filename = secure_filename(f.filename)

        if not f.mimetype.endswith("pcap"):
            return Response("Bad file", status=400)

        if os.path.exists("static/uploads"):
            pass
        else:
            os.mkdir("static/uploads")
        final_path = os.path.join("static/uploads", filename)
        f.save(final_path)
        os.system(f"python3 scripts/pcap_analyser.py static/uploads/{filename}")

        with open("tables/netcap_stats.html", "r") as f:
            netcap_stats = f.read()
        with open("tables/enum_images.html", "r") as f:
            enum_images = f.read()
        with open("tables/email_addrs.html", "r") as f:
            email_addrs = f.read()
        with open("tables/packet_count.html", "r") as f:
            packet_count = f.read()

        with open("results/line_graph_file.png", "rb") as f:
            line_graph = base64.b64encode(f.read()).decode('utf-8')

        with open("results/weighted_graph_file.png", "rb") as f:
            weighted_graph = base64.b64encode(f.read()).decode('utf-8')

        with open("results/results.kml", "r") as f:
            kml_contents = f.read()

        # shutil.rmtree("results", ignore_errors=True)
        shutil.rmtree("tables", ignore_errors=True)
        shutil.rmtree("static/uploads", ignore_errors=True)

        return render_template(
            "report.html",
            netcap_stats=netcap_stats,
            email_addrs=email_addrs,
            enum_images=enum_images,
            packet_count=packet_count,
            line_graph=line_graph,
            weighted_graph=weighted_graph,
            kml_contents=kml_contents
        )
    else:
        return Response("Not Found", status=404)


if __name__ == "__main__":
    app.run(debug=True, port=os.getenv("PORT", default=5000))
