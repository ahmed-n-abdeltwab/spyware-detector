const fileInput = document.querySelector("#file-input");
const container = document.querySelector(".container");
let fileForm = document.querySelector("#fileForm");
const resultDiv = document.querySelector("#result");
const apisDiv = document.querySelector("#api-list");
const errorDiv = document.querySelector("#error");
const loader = document.querySelector(".loader");
const fileContainer = document.querySelector("#file-container");
// spans for malwares and not malwares
const malware = "<span style='color:red;font-weight: bold;'>a Spyware</span>";
const notMalware =
  "<span style='color:green;font-weight: bold;'>Not a Spyware</span>";
const malapiURL = "https://malapi.io/winapi/";
const virustotalURL = "https://www.virustotal.com/gui/file/";

const handleError = (error) => {
  loader.classList.add("hide");
  fileContainer.classList.remove("hide");
  errorDiv.innerHTML = "";
  const paragraph = document.createElement("p");
  paragraph.style.color = "red";
  paragraph.style.textAlign = "center";
  console.log(error);
  paragraph.innerHTML = `Error: ${error.message}`;
  errorDiv.appendChild(paragraph);
};
const loading = () => {};
fileInput.addEventListener("change", async (e) => {
  // prevent the default action of the event
  e.preventDefault();
  // reset the result div and the apis div
  errorDiv.innerHTML = "";
  resultDiv.innerHTML = "";
  apisDiv.innerHTML = "";
  resultDiv.classList.add("hide");
  fileContainer.classList.add("hide");
  apisDiv.classList.add("hide");
  loader.classList.remove("hide");
  container.classList.add("col-1");
  container.classList.remove("col-2");
  container.classList.remove("col-3");
  // fetch the features from the scanner
  const formData = new FormData(fileForm);
  const scannerResult = await postData(
    // https://spyware-detector.herokuapp.com/
    // http://127.0.0.1:8000/
    "https://spyware-detector.herokuapp.com/api/v1/scanner",
    formData
  );
  // fetch the prediction from the classifier
  const classifierResult = await postData(
    "https://spyware-detector.herokuapp.com/api/v1/classifier",
    [scannerResult.features, scannerResult.details.apiList] // features and apiList of the scanner
  );
  // remove the loader
  loader.classList.add("hide");
  fileContainer.classList.remove("hide");
  // print the result of the classifier
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
  } catch (error) {
    handleError(error);
  }
});

const postData = async (url, data) => {
  try {
    return await axios
      .post(url, data)
      .then((response) => response.data)
      .catch((error) => handleError(error));
  } catch (error) {
    handleError(error);
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
