const mongoose=require("mongoose");

const db=async()=>{
    try{
        const connect=await mongoose.connect(process.env.MONGO_URL);
        console.log(`MongoDB connect ${connect.connection.host}`);
    }
    catch(err){
        console.log(err);
    }
}

module.exports=db;