const fileInput = document.querySelector("#fileInput");
let fileForm = document.getElementById("fileForm");
const DOMresult = document.querySelector("#result");

// spans for malwares and not malwares
const malware = "<span style='color:red;font-weight: bold;'>a Spyware</span>";
const notMalware =
  "<span style='color:green;font-weight: bold;'>Not a Spyware</span>";

fileInput.addEventListener("change", async (e) => {
  e.preventDefault();
  // fetch the features from the scanner
  const formData = new FormData(fileForm);
  const { features, API_list } = await postData(
    "http://127.0.0.1:4000/api/v1/scanner",
    formData
  );
  // fetch the prediction from the classifier
  const { prediction, details } = await postData(
    "http://127.0.0.1:4000/api/v1/classifier",
    [features, API_list]
  );
  const { name } = fileInput.files[0];
  printPrediction(name, prediction);
  if ("topReason" in details) {
    const { topReason } = details;
    printReasons(topReason);
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

const printPrediction = (filename, prediction) => {
  DOMresult.textContent = "";
  const h3Prediction = document.createElement("h3");
  h3Prediction.textContent = "Prediction :";

  const h5prediction = document.createElement("h5");
  h5prediction.innerHTML = `The file " ${filename} " is 
${prediction === -1 ? malware : notMalware}`;
  DOMresult.appendChild(h3Prediction);
  DOMresult.appendChild(h5prediction);
};

const printReasons = (topReason) => {
  const h4TopReason = document.createElement("h4");
  h4TopReason.textContent = "Top Reasons:";

  const olTopreason = document.createElement("ol");
  topReason.forEach((element) => {
    const li = document.createElement("li");
    li.textContent = element;
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
