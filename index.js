const express = require('express');
const path= require('path');
const bodyParser = require('body-parser');

var app = express();

app.set('views',path.join(__dirname, 'views'));
app.set('view engine','pug');
app.use(express.static(path.join(__dirname, './views/illustrations')))


app.get('/', function(req,res){
  res.render('home');
  require('console-stamp')(console, '[HH:MM:ss.l]', "Home Page");
  console.log("")
});

app.post('/', function(req, res){

  require('console-stamp')(console, '[HH:MM:ss.l]', "Start");
  console.log("")
  //var spawn = require("child_process");
  //var process = spawn.spawnSync('python3',["./parser.py"]);
  //var execSync = require('exec-sync');
  //var user = execSync('python3 parser.py');


  res.redirect('/results');

});

app.get('/results', function(req,res){
  var fs = require('fs');
  let data = fs.readFileSync("procmon.json");
  let obj = JSON.parse(data);
  //console.log(obj)
  res.render('results',{job_desc : [obj]});
});






const PORT= 8000;

app.listen(PORT, () => console.log(`Server started on ${PORT}`));
