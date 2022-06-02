
const fileInput = document.querySelector("#fileInput");
let fileForm = document.getElementById('fileForm');
const result = document.querySelector("#result");
// spans for malwares and not malwares
const malware = "<span style='color:red;font-weight: bold;'>a Spyware</span>";
const notMalware =
  "<span style='color:red;font-weight: bold;'>not a Spyware</span>";

fileInput.addEventListener("change", async (e) => {
  e.preventDefault();
  const formData = new FormData(fileForm);
  await axios
    .post("http://127.0.0.1:3000/uploud", formData)
    .then(response => {response.data})
    .then(({ prediction, details }) => {
      result.textContent = "";

      const h3Prediction = document.createElement("h3");
      h3Prediction.textContent = "Prediction :";

      const h5prediction = document.createElement("h5");
      h5prediction.innerHTML = ` The file : [${fileInput.files[0].name}] is 
  ${prediction == -1 ? malware : notMalware}`;

      const h4Top10reason = document.createElement("h4");
      h4Top10reason.textContent = "Top 10 reasons:";

      const olTop10reason = document.createElement("ol");
      details.top10reason.forEach((element) => {
        const li = document.createElement("li");
        li.textContent = element;
        olTop10reason.appendChild(li);
      });
      result.appendChild(h3Prediction);
      result.appendChild(h5prediction);
      result.appendChild(h4Top10reason);
      result.appendChild(olTop10reason);
    })
    .catch(err => console.log(err));
});
function run(e) {
  fileForm.submit()
}
document.onpaste = function (event) {
  urlInput = document.getElementById("urlInput");
  if (event.target == urlInput) {
    //don't interfere with paste to url box - allows ios to paste image links properly
    //give some time for paste to finish normally before checking
    setTimeout(function () {
      getURLInput(urlInput);
    }, 4);
    return;
  } else {
    event.preventDefault();
    clipboardData = event.clipboardData || event.originalEvent.clipboardData;
    if (typeof clipboardData.files[0] == "undefined") {
      urlInput.value = clipboardData.getData("Text");
      getURLInput(urlInput);
    } else {
      fileInput = document.getElementById("fileInput");
      fileInput.files = clipboardData.files;
      checkFile(fileInput);
    }
  }
};
document.ondragover = document.ondragenter = function (event) {
  event.preventDefault();
};
document.ondrop = function (event) {
  fileInput = document.getElementById("fileInput");
  if (event.target == fileInput) {
    //don't interfere with drop on file select - allows old browsers to drop properly
    //console.log("skipped drop!");
    return;
  } else {
    event.preventDefault();
    if (typeof event.dataTransfer.files[0] == "undefined") {
      urlInput = document.getElementById("urlInput");
      urlInput.value = event.dataTransfer.getData("text/uri-list");
      getURLInput(urlInput);
    } else {
      fileInput = document.getElementById("fileInput");
      fileInput.files = event.dataTransfer.files;
      checkFile(fileInput);
    }
  }
};
