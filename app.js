//jshint esversion:6

//새로 설치한 npm package : mogoose-encryption, dotenv, md5, bcrypt
//passport passport-local passport-local-mongoose express-session
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

//session- STEP1
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

// const md5 = require("md5");
// const encrypt = require("mongoose-encryption");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;


app.use(express.static("public"));
app.set("view engine","ejs");
app.use(bodyParser.urlencoded({
    extended: true
}));

//session- STEP2
app.use(session({
    secret: "Our little secret.",
    resave:false,
    saveUninitialized: false
}));

//session- STEP3
app.use(passport.initialize());
//session- STEP4
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser:true, 
// useUnifiedTopology: true, 
// useCreateIndex: true, 
// useFindAndModify: false 
});

//session- STEP7
//에러 떠서 해결해줌
mongoose.set("useCreateIndex", true);

//mongoose-encryption쓸꺼고 몽구스 스키마에 플러그인을 설치해줄 거기 때문에
//mongoose schema 써서 필요한 세팅을 미리 해줌
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId:String,
    secret:String
});

//session- STEP5
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//gitignore 만들때, .env랑 node_modules도 ignore 해주어야 함
// userSchema.plugin(encrypt,{secret:process.env.SECRET , encryptedFields: ["password"]});

const User = new mongoose.model("User",userSchema);
//session- STEP6
//serialise할 때, 쿠키를 만드는 것
//deserialise는 쿠키를 열람하는 것
passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
});


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/",function(req,res){
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate('google',{scope:["profile"]})
);

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login",function(req,res){
    res.render("login");
});

//session- STEP9
app.get("/secrets",function(req,res){
    
    // if(req.isAuthenticated()){
    //     res.render("secrets");
    // }else{
    //     res.redirect("/login");
    // }

    User.find({"secret":{$ne: null}},function(err,foundUsers){
        if(err){
            console.log(err);
            
        }else{
            if(foundUsers){
                res.render("secrets",{usersWithSecrets:foundUsers});
            }
        }
    });
});

app.get("/register",function(req,res){
    res.render("register");
});



app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});

app.post("/submit",function(req,res){
    const submittedSecret=req.body.secret;
    User.findById(req.user.id,function(err,foundUser){
        if(err){
            console.log(err);
            
        }else{
            if(foundUser){
                foundUser.secret=submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
            
        }
    });
});

//session- STEP11
app.get("/logout",function(req,res){
    //return 받은 user를 로그아웃 시켜줌 
    req.logout();
    res.redirect("/");
});






//session- STEP8
app.post("/register",function(req,res){
    User.register({username:req.body.username},req.body.password,function(err,user){
        if(err){
            console.log(err);
            res.redirect("/register");      
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });
});

//session- STEP10
app.post("/login",function(req,res){
    
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user,function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
        
        
    });

});

app.listen(3000,function(){
    console.log("Server is running on port 3000");
    
})

