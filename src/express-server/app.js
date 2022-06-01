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

    // // fetch the features from the scanner
    // const fileFeatures = await axios.post('http://127.0.0.1:6000/api/v1/scanner', {
    //     'data':req.file
    // })
    // .then(res => { return res.data })
    // .catch(error => console.log(error))
    fileFeatures = [1, 0, 1, 2, 3]
    // fetch the features from the classifier
    const prediction = await axios.post('http://127.0.0.1:6000/api/v1/classifier', {
        'features':fileFeatures
    })
    .then(res => { return res.data })
    .catch(error => console.log(error))

    res.json(prediction)
    // res.json({
    //     prediction:1,
    //     details:{
    //         prob:[0.5, 0.5], 
    //         top10reason:["reason1", "reason2","reason3"]
    //     }})
})
app.listen(port, hostname,  () => {
    console.log(`Example app listening on http://${hostname}:${port}/`)
})

