const express=require("express");
const helmet=require("helmet");
const morgan=require("morgan");
const cors=require("cors");
const path=require("path");

require("dotenv").config();
const port=process.env.PORT || 5000;

const db=require("./config/db");
db();

const app=express();

app.use(helmet());
app.use(morgan("dev"));
app.use(cors());
app.use(express.json());

app.use("/api/auth",require("./routes/authRouter"));

if(process.env.NODE_ENV==="production"){
    app.use(express.static(path.join(__dirname,"../frontend/build")));
    app.get("*",(req,res)=>{
        res.sendFile(path.resolve(__dirname,"../","frontend","build","index.html"));
    });
}

app.listen(port,()=>{
    console.log(`Server running ${port} port.`);
});