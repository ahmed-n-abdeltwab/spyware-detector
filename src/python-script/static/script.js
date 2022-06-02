
const fileInput = document.querySelector("#fileInput");
let fileForm = document.getElementById('fileForm');
const result = document.querySelector("#result");
// spans for malwares and not malwares
const malware = "<span style='color:red;font-weight: bold;'>a Spyware</span>";
const notMalware =
  "<span style='color:red;font-weight: bold;'>not a Spyware</span>";

async function postData(url = '', data = {}) {
    // Default options are marked with *
    const response = await fetch(url, {
      method: 'POST', // *GET, POST, PUT, DELETE, etc.
      mode: 'cors', // no-cors, *cors, same-origin
      cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
      credentials: 'same-origin', // include, *same-origin, omit
      headers: {
        'Content-Type': 'application/json'
        // 'Content-Type': 'application/x-www-form-urlencoded',
      },
      redirect: 'follow', // manual, *follow, error
      referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
      body: JSON.stringify(data) // body data type must match "Content-Type" header
    });
    return response.json(); // parses JSON response into native JavaScript objects
  }

fileInput.addEventListener("change", async (e) => {
  e.preventDefault();
  const formData = new FormData(fileForm);
  // await fetch('http://127.0.0.1:5000/api/v1/scanner', formData)
  // .then(response => response.json())
  // .then(result => {
  //   console.log('Success:', result);
  // })
  // .catch(error => {
  //   console.error('Error:', error);
  // });
  let fileFeatures;
  await axios.post(
    'http://127.0.0.1:4000/api/v1/scanner', formData)
    .then(response => response.data)
    .then(({features, size}) => {
      fileFeatures = features;
    })
    .catch(error => {console.log(error)});
    console.log(fileFeatures)
  //   // fetch the features from the classifier
    
  //   const prediction = await axios.post(
  //       'http://127.0.0.1:6000/api/v1/classifier', fileFeatures)
  //   .then(response => {response.data})
  //   .then(({ prediction, details }) => {
  //     result.textContent = "";

  //     const h3Prediction = document.createElement("h3");
  //     h3Prediction.textContent = "Prediction :";

  //     const h5prediction = document.createElement("h5");
  //     h5prediction.innerHTML = ` The file : [${fileInput.files[0].name}] is 
  // ${prediction == -1 ? malware : notMalware}`;

  //     const h4Top10reason = document.createElement("h4");
  //     h4Top10reason.textContent = "Top 10 reasons:";

  //     const olTop10reason = document.createElement("ol");
  //     details.top10reason.forEach((element) => {
  //       const li = document.createElement("li");
  //       li.textContent = element;
  //       olTop10reason.appendChild(li);
  //     });
  //     result.appendChild(h3Prediction);
  //     result.appendChild(h5prediction);
  //     result.appendChild(h4Top10reason);
  //     result.appendChild(olTop10reason);
  //   })
  //   .catch(error => {console.log(error)});

});

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
