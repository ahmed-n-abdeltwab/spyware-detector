const express = require('express')
const axios = require('axios');
const fileUpload = require("express-fileupload");
const FormData = require('form-data');
const path = require('path');

const app = express()
const port = 3000;
const hostname = "127.0.0.1";


app.use(express.static("./public"))
app.use(express.urlencoded({extended:true}));
app.use(express.json());
app.use(fileUpload({
      limits: { fileSize: 50 * 1024 * 1024 }
    })
  );
app.set('views', path.resolve(__dirname, './views'))

app.get('/', (req, res) => {
    res.sendFile(app.get('views') + '/index.html')
})

app.post('/uploud', async (req, res) => {
    // fetch the features from the scanner
    const form = new FormData();
    form.append('data', req.files.uploaded_file.data,{
        name:req.files.uploaded_file.name,
        size:req.files.uploaded_file.size,
        tempFilePath:req.files.uploaded_file.tempFilePath,
        truncated:req.files.uploaded_file.truncated,
        mimetype:req.files.uploaded_file.mimetype,
        md5:req.files.uploaded_file.md5,
        mv:req.files.uploaded_file.mv,
    });
    // console.log(req.files.uploaded_file.data)
    const fileFeatures = await axios.post('http://127.0.0.1:6000/api/v1/scanner', form)
    .then(response => console.log(typeof(response)))
    .then(result => result.files)
    .catch(error => {return res.status(400).send(error)});
    // console.log(fileFeatures)
    // fetch the features from the classifier
    
    const prediction = await axios.post(
        'http://127.0.0.1:6000/api/v1/classifier', fileFeatures)
    .then(response => response)
    .catch(error => {return res.status(400).send(error)});

    res.json(prediction);
})
app.listen(port, hostname,  () => {
    console.log(`Example app listening on http://${hostname}:${port}/`)
})

