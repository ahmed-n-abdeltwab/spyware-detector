const fileInput = document.querySelector("#fileInput");
let fileForm = document.getElementById("fileForm");
const DOMresult = document.querySelector("#result");

// spans for malwares and not malwares
const malware = "<span style='color:red;font-weight: bold;'>a Spyware</span>";
const notMalware =
  "<span style='color:green;font-weight: bold;'>Not a Spyware</span>";
const malapiAPI = "https://malapi.io/winapi/";
const virustotalAPI = "https://www.virustotal.com/gui/file/";

fileInput.addEventListener("change", async (e) => {
  e.preventDefault();
  // fetch the features from the scanner
  const formData = new FormData(fileForm);
  const { features, details: fileDetails } = await postData(
    "http://127.0.0.1:4000/api/v1/scanner",
    formData
  );
  const { API_list, fileHash, entropy } = fileDetails;

  // fetch the prediction from the classifier
  const { prediction, details: predDetails } = await postData(
    "http://127.0.0.1:4000/api/v1/classifier",
    [features, API_list]
  );
  const { name } = fileInput.files[0];

  printPrediction(name, prediction, fileHash, entropy);
  if ("topReason" in predDetails) {
    const { topReason } = predDetails;
    if (topReason.length > 0) printReasons(topReason);
  }
});

const postData = async (url, data) => {
  try {
    return await axios
      .post(url, data)
      .then((response) => response.data)
      .catch((error) => console.log(error));
  } catch (error) {
    console.log(error);
  }
};

const printPrediction = (filename, prediction, fileHash, entropy) => {
  DOMresult.textContent = "";
  const h3Prediction = document.createElement("h3");
  h3Prediction.textContent = "Prediction :";

  const pPrediction = document.createElement("p");
  pPrediction.innerHTML = `The file " ${filename} " is 
${prediction === -1 ? malware : notMalware}`;
  const pFileHash = document.createElement("p");
  pFileHash.innerHTML =
    "<a href='" +
    virustotalAPI +
    fileHash +
    "' target='_blank'>Hash : " +
    fileHash +
    "</a>";
  const pEntropy = document.createElement("p");
  pEntropy.textContent = `The file Entropy : ${entropy}`;
  DOMresult.appendChild(h3Prediction);
  DOMresult.appendChild(pPrediction);
  DOMresult.appendChild(pFileHash);
  DOMresult.appendChild(pEntropy);
};

const printReasons = (topReason) => {
  const h4TopReason = document.createElement("h4");
  h4TopReason.textContent = "The used APIs:";

  const olTopreason = document.createElement("ol");
  topReason.forEach((element) => {
    const li = document.createElement("li");
    li.innerHTML =
      "<a href='" +
      malapiAPI +
      element +
      "' target='_blank'>" +
      element +
      "</a>";
    olTopreason.appendChild(li);
  });
  DOMresult.appendChild(h4TopReason);
  DOMresult.appendChild(olTopreason);
};

// document.onpaste = function (event) {
//   urlInput = document.getElementById("urlInput");
//   if (event.target == urlInput) {
//     //don't interfere with paste to url box - allows ios to paste image links properly
//     //give some time for paste to finish normally before checking
//     setTimeout(function () {
//       getURLInput(urlInput);
//     }, 4);
//     return;
//   } else {
//     event.preventDefault();
//     clipboardData = event.clipboardData || event.originalEvent.clipboardData;
//     if (typeof clipboardData.files[0] == "undefined") {
//       urlInput.value = clipboardData.getData("Text");
//       getURLInput(urlInput);
//     } else {
//       fileInput = document.getElementById("fileInput");
//       fileInput.files = clipboardData.files;
//       checkFile(fileInput);
//     }
//   }
// };
// document.ondragover = document.ondragenter = function (event) {
//   event.preventDefault();
// };
// document.ondrop = function (event) {
//   fileInput = document.getElementById("fileInput");
//   if (event.target == fileInput) {
//     //don't interfere with drop on file select - allows old browsers to drop properly
//     //console.log("skipped drop!");
//     return;
//   } else {
//     event.preventDefault();
//     if (typeof event.dataTransfer.files[0] == "undefined") {
//       urlInput = document.getElementById("urlInput");
//       urlInput.value = event.dataTransfer.getData("text/uri-list");
//       getURLInput(urlInput);
//     } else {
//       fileInput = document.getElementById("fileInput");
//       fileInput.files = event.dataTransfer.files;
//       checkFile(fileInput);
//     }
//   }
// };
