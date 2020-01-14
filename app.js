//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const app = express();
const encrypt = require("mongoose-encryption");

app.use(express.static("public"));
app.set("view engine","ejs");
app.use(bodyParser.urlencoded({
    extended: true
}));

mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser:true, 
useUnifiedTopology: true, 
useCreateIndex: true, 
useFindAndModify: false });

//mongoose-encryption쓸꺼고 몽구스 스키마에 플러그인을 설치해줄 거기 때문에
//mongoose schema 써서 필요한 세팅을 미리 해줌
const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

//gitignore 만들때, .env랑 node_modules도 ignore 해주어야 함
userSchema.plugin(encrypt,{secret:process.env.SECRET , encryptedFields: ["password"]});

const User = new mongoose.model("User",userSchema);

app.get("/",function(req,res){
    res.render("home");
});

app.get("/login",function(req,res){
    res.render("login");
});

app.get("/register",function(req,res){
    res.render("register");
});

app.post("/register",function(req,res){
    const newUser = new User({
        email: req.body.username,
        password: req.body.password
    });

    newUser.save(function(err){
        if(err){
            console.log(err);  
        }else{
            res.render("secrets");
        }
    });
});

app.post("/login",function(req,res){
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({email:username},function(err,foundUser){
        if(err){
            console.log(err);
            
        }else{
            if(foundUser){
                if(foundUser.password === password){
                    res.render("secrets");
                }
            }
            
        }
    });
});

app.listen(3000,function(){
    console.log("Server is running on port 3000");
    
})

