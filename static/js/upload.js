const s = document.getElementById("submit-btn");
s.addEventListener("click", (e) => {
  uploadFile();
});

function uploadFile() {
  const fileInput = document.getElementById("file");
  let data = new FormData();
  data.append("file", fileInput.files[0]);

  fetch("/upload", {
    method: "POST",
    body: data,
  }).then();
}
