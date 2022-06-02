const express = require('express')
const axios = require('axios');
const multer  = require('multer')
const path = require('path')

const app = express()
const port = 3000;
const hostname = "127.0.0.1";


app.use(express.static("./public"))
app.use(express.urlencoded({extended:true}))
app.use(express.json())

app.set('views', path.resolve(__dirname, './views'))

app.get('/', (req, res) => {
    res.sendFile(app.get('views') + '/index.html')
})

app.post('/uploud', multer().single('uploaded_file'), async (req, res) => {
    // fetch the features from the scanner
    console.log(req.file, req.body)
    const fileFeatures = await axios.post('http://127.0.0.1:6000/api/v1/scanner', {
        'data':req.file
    })
    .then(res => { return res.data })
    .catch(error => console.log("error", "error [fileFeatures]"))

    // fetch the features from the classifier
    const prediction = await axios.post('http://127.0.0.1:6000/api/v1/classifier', {
        'features':fileFeatures
    })
    .then(res => { return res.data })
    .catch(error => console.log("error", "error [prediction]"))

    res.json(prediction)
})
app.listen(port, hostname,  () => {
    console.log(`Example app listening on http://${hostname}:${port}/`)
})

