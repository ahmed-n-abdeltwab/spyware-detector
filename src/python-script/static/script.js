const fileInput = document.querySelector("#file-input");
const container = document.querySelector(".container");
let fileForm = document.querySelector("#fileForm");

// spans for malwares and not malwares
const malware = "<span style='color:red;font-weight: bold;'>a Spyware</span>";
const notMalware =
  "<span style='color:green;font-weight: bold;'>Not a Spyware</span>";
const malapiURL = "https://malapi.io/winapi/";
const virustotalURL = "https://www.virustotal.com/gui/file/";

fileInput.addEventListener("change", async (e) => {
  e.preventDefault();
  // fetch the features from the scanner
  const formData = new FormData(fileForm);
  const scannerResult = await postData(
    "http://127.0.0.1:4000/api/v1/scanner",
    formData
  );

  // fetch the prediction from the classifier
  const classifierResult = await postData(
    "http://127.0.0.1:4000/api/v1/classifier",
    [scannerResult.features, scannerResult.details.apiList] // features and apiList of the scanner
  );

  const predictionResult = {
    name: fileInput.files[0].name,
    prediction: classifierResult.prediction,
    fileHash: scannerResult.details.fileHash,
    entropy: scannerResult.details.entropy,
  };
  try {
    printPrediction(predictionResult);
    if ("apiList" in classifierResult.details) {
      if (classifierResult.details.apiList.length > 0)
        printAPIsList(classifierResult.details.apiList); // print the APIs for the prediction from many resources
    }
    divUnhider();
  } catch (error) {
    console.log(error);
  }
});

const postData = async (url, data) => {
  try {
    return await axios
      .post(url, data)
      .then((response) => response.data)
      .catch((error) => console.log(error));
  } catch (error) {
    alart(error);
  }
};
// print the result of the classifier
const printPrediction = (predictionResult) => {
  /**
   * @param {string} predictionResult.name
   * @param {int} predictionResult.prediction
   * @param {string} predictionResult.fileHash
   * @param {float} predictionResult.entropy
   */
  const resultDiv = document.querySelector("#result");
  resultDiv.classList.remove("hide");
  container.classList.remove("col-1");
  container.classList.add("col-2");
  const { name: filename, prediction, fileHash, entropy } = predictionResult;
  const content = `
  <h3>File Name  : ${filename}</h3>
  <h3>Prediction : ${prediction === 0 ? malware : notMalware}</h3>
  <h3>Hash       : <a href="${virustotalURL}${fileHash}" target="_blank">${fileHash}</a></h3>
  <h3>Entropy    : ${entropy}</h3>
  `;
  resultDiv.innerHTML = content;
};

// print the reasons for the prediction
const printAPIsList = (APIs) => {
  const apisDiv = document.querySelector("#api-list");
  apisDiv.classList.remove("hide");
  container.classList.remove("col-2");
  container.classList.add("col-3");
  const content = `
  <h3>Used APIs :</h3>
  <ul>
  ${APIs.map(
    (api) => `<li><a href="${malapiURL}${api}" target="_blank">${api}</a></li>`
  ).join("")}
  </ul>`;
  apisDiv.innerHTML = content;
};

// Styling the page according to the screen size

window.onresize = (event) => {
  const hideItems = document.querySelectorAll(".hide");
  if (hideItems.length === 0) {
    if (document.body.clientWidth > 800) {
      container.classList.remove("col-1");
      container.classList.add("col-3");
    } else {
      container.classList.add("col-1");
      container.classList.remove("col-3");
    }
  }
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
