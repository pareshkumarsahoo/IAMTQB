import express from 'express';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import bcrypt, { hash } from 'bcrypt';
import cors from "cors";



//app config
const app = express();
const PORT = process.env.PORT || 8001;
const connectionURL  ="mongodb+srv://Admin:Admin123@cluster0.unff6.mongodb.net/myFirstDatabase?retryWrites=true&w=majority";

const user = mongoose.Schema({
    _id:mongoose.Schema.Types.ObjectId,
    userId:String,
    name:String,
    password:String,
    isAdmin:Boolean
       
})

const staticData = {
    mainGate:{
        status:'Active',
        mainGateStatus:'Closed',
        visitorCount:21,
        security:{
            data:[
                {
                    name:'Wel Jone',
                    rank:'Level 2',
                    status:'Active'
                },
                {
                    name:'jas NewMan',
                    rank:'Level 2',
                    status:'Active'
                },
                {
                    name:'Sam Crook',
                    rank:'Squadron',
                    status:'InActive'
                }
            ],
            activeCount:2
        }

    },
    camera:{
        
        data:[
            {
                camId:12,
                momentDeteted:33,
                status:'Active'
            },
            {
                camId:10,
                momentDeteted:127,
                status:'Active'
            },
            {
                camId:9,
                momentDeteted:892,
                status:'InActive'
            }
        ],
        activeCount:2

    },
    routers:{
        status:'Active',
        lastReboot:'2018-09-06 12:42:53.885',
        camDetails:{
            data:[
                {
                    camId:12,
                    momentDeteted:33,
                    status:'Active'
                },
                {
                    camId:10,
                    momentDeteted:127,
                    status:'Active'
                },
                {
                    camId:9,
                    momentDeteted:892,
                    status:'InActive'
                }
            ],
            activeCount:2
        },
        cnnectedIps:[
            "192.234.34.42",
            "192.234.34.10",
            "192.2344.34.12",
            "192.234.34.02",
            "192.234.34.11",
        ]

    }
}

const User = mongoose.model('User',user)

//middleware
app.use(express.json())
app.use(cors())


// DB config
mongoose.connect(connectionURL,{
    useNewUrlParser:true,
    useUnifiedTopology:true
})



//api endpoints
app.get('/api/',(req,res)=>{
    res.status(200).send("IAM API BASE")
});

//Register

app.post('/api/register',(req,res)=>{

    User.find({userId:req.body.userId})
    .exec()
    .then(user =>{
        if(user.length>0){
            return res.status(409).json({
                message : "User already exists"
            })
        }else{

            bcrypt.hash(req.body.password,10,(err ,hash)=>{
                if(err){
                    return res.status(500).json({
                        error:err
                    })
                }else{
                    const userDeatils = new User({
                        _id:new mongoose.Types.ObjectId(),
                        userId:req.body.userId,
                        name:req.body.name,
                        password:hash,
                        isAdmin:req.body.isAdmin
                       });
                    userDeatils.save().then(result =>{
                        res.status(201).json({
                            status:true,
                            message:"Registred Succesfully"
                        })
                    })
                    .catch(err =>{
                        res.status(500).json({
                            message:err
                        })
                    })
                }
            })
        
        }

    })
    .catch(err =>{
        res.status(500).json({
            message:err
        })
    })
});



//Login

app.post('/api/login', (req,res)=>{
    User.find({userId:req.body.userId})
    .exec()
    .then(user=>{
        if(user.length<1){
            return res.status(401).json({
                message : "No User Exist with this UserId"
            })
        }else{
            bcrypt.compare(req.body.password,user[0].password,(err,result)=>{
                if(err){
                    return res.status(401).json({
                        message:'Access Denied',
                        
                        err:err
                    })
                }
                if(result){
                   const token = jwt.sign({
                        name:user[0].userId,
                        userID:user[0]._id,
                        isAdmin:user[0].isAdmin

                    },"SecretJWTKey")
                    return res.status(200).json({
                        message:'Permission Granted',
                        user:user[0].name,
                        status:true,
                        acessToken:token,
                    })
                }
               res.status(401).json({
                        message:'Access Denied',
                        err:"No Match"

                    })
                
            })
        }
    })
    .catch(err=>{
        res.status(401).json({
            message:"Access Denied",
            err:err
        })
    });
})

//Access Main gate

app.get('/api/acessMainGate', verifyToken, (req,res)=>{

    jwt.verify(req.token, 'SecretJWTKey' ,(err,authData)=>{
        if(err){
            res.status(403).json({
                message:'Access Denied'
            })
        }else{

            res.status(200).send(staticData.mainGate);
                    
               
        }
    });
    

})



//Access Camera

app.get('/api/accessCamera', verifyToken, (req,res)=>{

    jwt.verify(req.token, 'SecretJWTKey' ,(err,authData)=>{
        if(err){
            res.status(403).json({
                message:'Access Denied'
            })
        }else{
            res.status(200).send(staticData.camera);
          
        }
    });
    
})




//Access Router Config

app.get('/api/accessRouter', verifyToken, (req,res)=>{

    jwt.verify(req.token, 'SecretJWTKey' ,(err,authData)=>{
        if(err){
            res.status(403).json({
                message:'Access Denied'
            })
        }else{
            if(authData.isAdmin){
                res.status(200).send(staticData.routers);
            }else{
                res.status(403).json({
                    message:'Access Denied NON-ADMIN'
                })
            }    
        }
    });
    

})



function verifyToken(req ,res ,next){
    const bearerHeader = req.headers['authorization'];
    if(typeof bearerHeader !== 'undefined'){
        const token = bearerHeader.split(' ')
        req.token = token[1];
        next();
    }else{
        res.status(403).json({
            message:'Access Denied',
        });
    }



}




//listner
app.listen(PORT,()=>console.log(`listning on local host ${PORT}`))

