import os
from uuid import uuid4

from flask import Flask, Response, render_template, request
from werkzeug.utils import secure_filename

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("home.html")


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html")


@app.route("/upload", methods=["POST"])
def file_upload():

    if request.method == "POST":

        f = request.files["file"]
        filename = secure_filename(f.filename)

        if not f.mimetype.endswith("pcap"):
            return Response("Bad file", status=400)
        else:

            if os.path.exists("uploads"):
                pass
            else:
                os.mkdir("uploads")

            f.save(os.path.join("uploads", filename))
            x = uuid4()
            return f"https://localhost:5000/results/{x}.pdf"



if __name__ == "__main__":
    app.run(debug=True, port=os.getenv("PORT", default=5000))
