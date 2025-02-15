const express = require('express');
const mysql=require('mysql');
const multer = require('multer');
const cors = require('cors');
require('dotenv').config()
const session = require("express-session");
const path=require("path");
const moment=require('moment')
const cookieParser=require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt=require('bcrypt');
const passport = require('passport');
const GoogleStrategy = require("passport-google-oauth20").Strategy;
// const allowedOrigins=[
//     "https://flashtag.netlify.app",
//       "http://localhost:5173"
// ]
const app= express();
// app.use(cors({
//     origin: "https://flashtag.netlify.app",
//     methods: ['GET', 'POST', 'PUT', 'DELETE'],
//     credentials:true
// }));
  
  app.use(cors({
    origin:"http://localhost:5173",
    credentials: true
  }));
// app.use(session({ secret: process.env.SECRECT_KEY, resave: false, saveUninitialized: true }));
app.use(session({
    secret: process.env.SECRECT_KEY,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, sameSite: "none" } // ✅ Required for cross-origin
}));
app.use(passport.initialize());
app.use(passport.session());
passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: `https://flashtagbackend.onrender.com/auth/google/callback`,
            scope: ["profile", "email"],
          },
          (accessToken, refreshToken, profile, done) => {
            return done(null, profile);
          }  
    )
);
function queryAsync(query, values) {
    return new Promise((resolve, reject) => {
      db.query(query, values, (err, result) => {
        if (err) {
          return reject(err);  // Reject the promise if an error occurs
        }
        resolve(result);  // Resolve the promise with the result
      });
    });
  }
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));
app.get("/auth/google", passport.authenticate("google", { scope: ["email", "profile"] }));
app.get('/login',(req,res)=>{
    res.json("unathorized usage")
})
app.get("/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/login" }),
    (req, res) => {
        const { id, displayName, emails, photos } = req.user;
        console.log("User data:", req.user); 
        const email = emails[0].value;

        const q=`select * from auth where email = ?`
       db.query(q,[email],async(err,data)=>{
        if(err) res.status(500).json(err);
         if(data.length>0){
            try {
                const re=await queryAsync(`update auth set online=? where email=?`,["true",data[0].email])
                console.log("thenila irunthu")
                const token =jwt.sign({id:data[0].id,name:data[0].username,profile:data[0].profiePic},process.env.SECRECT_KEY,{expiresIn:"4h"})
                res.cookie("accesstoken",token,{
                      sameSite:"lax",
                      secure:false,
                    path:"/"
                }).status(200).redirect('http://localhost:5173')
               
            } catch (error) {
               res.status(500).json(error)
            }
           
         }else{
            
            const pass= await Math.floor(Math.random()*10000000);
            const hashedPassword= await bcrypt.hash(pass.toString(),10)
            console.log(hashedPassword)
            try {
                const q=`insert into auth(username,email,password) values(?,?,?)`;
                const result = await queryAsync(q, [displayName, email, hashedPassword]); 
                const data3=await queryAsync(`select * from auth where email=?`,[email]);
                console.log(data3,"data3")
                const updateonline=await queryAsync(`update auth set online=? where id=?`,["true",data3[0].id]);
                console.log(updateonline,"updated")
                const token =jwt.sign({id:data3[0].id,name:data3[0].username,profile:data3[0].profiePic},process.env.SECRECT_KEY,{expiresIn:"4h"})
                res.cookie("accesstoken",token,{
                    sameSite:"lax",
                   secure:false,
                   path:'/'
                }).status(200).redirect('http://localhost:5173')
             
             }
                 catch (err) {
                    console.log(err)
                res.status(500).json(err); // Catching errors if any occur
            }
         }
       })
    }

)
const verifyJWT=(req,res,next)=>{
    const token = req.cookies.accesstoken;
    console.log(token,"token da")
    if (!token) {
        return res.status(401).json('Access denied');
    }
    try {
        const verified = jwt.verify(token, process.env.SECRECT_KEY);
        req.auth = verified; // Changed from req.user to req.auth
        console.log(verified)
        next();
    } catch (err) {
        res.status(400).json('Invalid token');
        res.clearCookie('accesstoken');
    }

}
app.use('/images', express.static(path.join(__dirname, '../client/images')));
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, '../client/images');
    },
    filename: (req, file, cb) => {
      cb(null, Date.now() + path.extname(file.originalname)); // Ensure unique file name
    },
  });
  const upload = multer({ storage });
app.post("/addpost",upload.single('image'),(req,res)=>{
    const q=`insert into post(img,des,createdAt,userId) values(?,?,?,?)`
  db.query(q,[req.file.filename,req.body.desc,moment(Date.now()).format('YYYY-MM-DD HH:mm:ss'),req.body.userId],(err,data)=>{
    if(err) console.log(err);
    res.json(data)
  })

})

app.use(cookieParser());
app.use(express.json());
const db=mysql.createConnection({
    host:process.env.MYSQL_HOST,
    user:process.env.MYSQL_USER,
    password:process.env.MYSQL_PASSWORD,
    database:process.env.MYSQL_DB,
     charset: 'utf8mb4',
     port:process.env.MYSQL_PORT
})

app.post('/user-register',(req,res)=>{
    const q=`select * from auth where email = ?`
    db.query(q,[req.body.email],async(err,data)=>{
        if(err) res.status(500).json(err)
        if(data.length>0){
            res.status(409).json('email already exists ')
        } else{
            const hashedPassword=await bcrypt.hash(req.body.password,10)           
            const q = `insert into auth(username,email,password) values (?,?,?)`
            db.query(q,[req.body.name,req.body.email,hashedPassword],(err,data)=>{
                if(err) res.status(500).json(err)
                else res.status(200).json('user created successfully')    
            })
        }   
    })
})

app.post('/user-login',(req,res)=>{
  const q=`select * from auth where email = ?`
    console.log(req.body.email,req.body.password)
   db.query(q,[req.body.email],async(err,data)=>{
    if(err) res.status(500).json(err);
    if(data.length>0){
        console.log(data)
        const isCorrectPassword=await bcrypt.compare(req.body.password,data[0].password);
        if(!isCorrectPassword) res.status(400).json("incorrect email or password");
        else {
            const q=`update auth set online=? where email=?`
            db.query(q,["true",req.body.email],(err,data2)=>{
                if(err) res.json(err);
                else{
                    const token =jwt.sign({id:data[0].id,name:data[0].username,profile:data[0].profiePic},process.env.SECRECT_KEY,{expiresIn:"4h"})
                    res.cookie("accesstoken",token,{
                        sameSite:"lax",
                       secure:false,
                       path:"/"
                    }).status(200).json({message:'logged in successfully',data:token})
                }
            })
           
        }
    }else{
        res.status(400).json("invalid email or password")
    }
   })


})
app.post('/logout/:id',(req,res)=>{
    const q=`update auth set online=? where id=?`;
    
    db.query(q,["false",req.params.id],(err,data)=>{
        if(err) res.status(500).json(err);
        else{
           res.clearCookie("accesstoken",{
            sameSite:"lax",
            secure:false,
            path:"/"
           }).status(200).json({message:'logged out successfully'}) 
        }
    })
})

 

    app.get('/getcomment/:postId',(req,res)=>{
        const q=`SELECT c.userId, c.postId, c.content,a.username AS commenter,a.profiePic AS commenterprofile,c.createdAt FROM comment c JOIN auth a ON c.userId=a.id WHERE postId=? ORDER BY c.createdAt DESC`
      db.query(q,[req.params.postId],(err,data)=>{
        if (err) res.status(500).json(err);
        else res.json(data)
      })
    
    })
    app.post('/postcomment/:userId/:postId',(req,res)=>{
       
      const q=`insert into comment(userId,postId,content,createdAt) values(?,?,?,?)`;
       db.query(q,[req.params.userId,req.params.postId,req.body.content,moment(Date.now()).format("YYYY-MM-DD HH:mm:ss")],(err,data)=>{
        if (err) res.status(500).json("comment not post");
        else res.json(data)
       })
    })

app.get('/gethome/:userId',verifyJWT,(req,res)=>{
    // res.json(req.auth.name);
     console.log(req.cookies)
   const userid=req.params.userId
    const q=`SELECT 
            a.username AS PostAuthor, 
            p.id AS PostId,
            p.userId As postUserId,
            p.img AS post,
            a.profiePic AS profile, 
            p.des AS description, 
            p.createdAt AS time 
        FROM post p 
        JOIN auth a ON p.userId = a.id 
        WHERE p.userId = ?

        UNION

        SELECT 
            a.username AS PostAuthor,
             p.id AS PostId,
             p.userId As postUserId,
            p.img AS post,  
             a.profiePic AS profile,                  
            p.des AS description, 
            p.createdAt AS time 
        FROM post p 
        JOIN auth a ON p.userId = a.id 
        JOIN follows f ON f.followedId = p.userId 
        WHERE f.followerId = ?
        ORDER BY time DESC;`
    db.query(q,[userid,userid],(err,data)=>{
        if(err) console.log(err);
        else {
            const q=`select a.profiePic,a.coverPic,a.online from auth a where a.id=?`
            db.query(q,[userid],(err,profile)=>{
                if(err) res.status(500).json(err);
                else{
                    res.json({data,profile})
                }
            })
            
        }
    })
})
app.get('/getfollowers/:userId',(req,res)=>{
     const q=`SELECT f.followerId FROM follows f WHERE f.followedId=?`;
     db.query(q,[req.params.userId],(err,data)=>{
        if(err) res.status(500).json(err);
        else res.json(data.map(user=>user.followerId))
     })

})
app.get('/online/:userId',(req,res)=>{
    const q=`SELECT f.followedId,a.online,a.id,a.username,a.profiePic FROM follows f JOIN auth a ON a.id=f.followedId  WHERE f.followerId=? AND a.online=?;`;
    db.query(q,[req.params.userId,"true"],(err,data)=>{
       if(err) res.status(500).json(err);
       else res.json(data)
    })

})
app.get('/getlikes/:postId',(req,res)=>{
    const q=`select userId from likes where postId=? `
    db.query(q,[req.params.postId],(err,data)=>{
        if(err) res.status(500).json(err);
        else {
         res.json(data.map(d=>d.userId))
        }
    })
})
app.post('/add-like/:userId/:postId',(req,res)=>{
 
    const q=`insert into likes(userId,postId) values(?,?) `
    db.query(q,[req.params.userId,req.params.postId],(err,data)=>{
        if(err) res.status(500).json(err);
        else res.json(data)
    })
})
app.get('/userProfile/:userId',verifyJWT,(req,res)=>{
    const q=`SELECT a.username,a.profiePic,a.coverPic from auth a where a.id=?`
     db.query(q,[req.params.userId],(err,data)=>{
        if(err) res.status(500).json(err);
         else{
            const q=`SELECT a.username AS PostAuthor,a.profiePic AS profile,a.coverPic AS coverpic ,p.img AS post,p.userId AS postUserId,p.id AS PostId,p.des AS description,p.createdAt AS time FROM auth a JOIN post p ON p.userId=a.id WHERE a.id=? ORDER BY p.createdAt DESC`;
             db.query(q,[req.params.userId],(err,result)=>{
                if(err) res.status(500).json(err);
                else res.json({userdetails:data,posts:result})
             })
            
         }
     })
})
app.put('/update/user/:userId',upload.fields([{ name: 'profilePic' }, { name: 'coverPic' }]),verifyJWT,(req,res)=>{
    
    const q =`select a.profiePic,a.coverPic from auth a where a.id=?`
    db.query(q,[req.params.userId],(err,data)=>{
        if(err) res.status(500).json(err);
        let olderCoverPic=data[0].coverPic;
        let olderProfilePic=data[0].profiePic;
        const profilePic=req.files['profilePic']?req.files['profilePic'][0].filename:olderProfilePic
        const coverPic=req.files['coverPic']?req.files['coverPic'][0].filename:olderCoverPic;
        const q='Update auth set coverPic=?,profiePic=? where id=?';
        db.query(q,[coverPic,profilePic,req.params.userId],(err,result)=>{
            if(err) res.status(500).json(err)
            if(result.affectedRows===0){
                res.status(403).json("update you profile only")
            }  else{
                res.status(200).json(result)
            }  
        })
    })

})
app.delete('/deletlike/:userId/:postId',(req,res)=>{
    const q=`delete from likes where userId=? and postId=?`
    db.query(q,[req.params.userId,req.params.postId],(err,data)=>{
        if(err) res.status(500).json(err);
        else res.json(data)
    })
})
app.get('/getusers/:id',(req,res)=>{
    const q=`SELECT a.id, a.username, a.profiePic, a.coverPic FROM auth a LEFT JOIN follows f ON f.followedId = a.id AND f.followerId = ? WHERE f.followedId IS NULL AND a.id != ?`
    db.query(q,[req.params.id,req.params.id],(err,data)=>{
        if(err) res.status(500).json(err);
        else res.json(data)
    })
})
app.post('/follow/:followerId/:followedId',(req,res)=>{

    const q=`insert into follows(followerId,followedId) values(?,?)`;
    db.query(q,[req.params.followerId,req.params.followedId],(err,data)=>{
        if(err) res.status(500).json(err);
        else res.json(data)
    })
})
app.delete('/unfollow/:followerId/:followedId',(req,res)=>{

    const q=`delete from follows where followerId=? and followedId=?`;
    db.query(q,[req.params.followerId,req.params.followedId],(err,data)=>{
        if(err) res.status(500).json(err);
        else res.json(data)
    })
})
app.delete('/deletPost/:postId',verifyJWT,(req,res)=>{
    const q=`delete from post where userId=? and id=?`;
    db.query(q,[req.auth.id,req.params.postId],(err,data)=>{
        if(err) res.status(500).json(err);
        if(data.affectedRows===0){
            res.status(403).json('unathorized post delete')
        }else{
            res.json(data)
        }
    })
})

app.get('/search',(req,res)=>{

    const q=`select a.id,a.username,a.profiePic from auth a where a.username like ?`;

    db.query(q,[`%${req.query.value}%`],(err,data)=>{
        if(err) res.json(err);
        else{
         res.json(data)
        }
    })

})
db.connect((err)=>{
    if(err){
        console.log(err)
    }else{
        console.log('db connected')
    }
})
 const PORT=process.env.PORT || 5000;
app.listen(process.env.PORT,()=>{
    console.log('app listening',process.env.PORT)
})