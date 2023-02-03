const bcrypt=require("bcrypt");
const jwt=require("jsonwebtoken");
const nodemailer=require("nodemailer");

const User=require("../models/userModel");
const dateTime=require("../utils/dateTime");

// 註冊
const register=async(req,res)=>{
    try{
        const {username,email,password,confirmPassword}=req.body;
        const emailPattern=/^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
		const passwordPattern=/^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,}$/;

        // 檢查全部欄位是否填寫
        if(!username || !email || !password || !confirmPassword){
            return res.status(400).json({
                message: "請填寫完整"
            });
        }
        // 檢查Email格式是否符合
        if(!email.match(emailPattern)){
            return res.status(400).json({
                message: "Email格式錯誤"
            });
        }
		// 檢查密碼長度是否大於8個字元
        if(password.length<8){
			return res.status(400).json({
                message: "密碼8位以上"
            });
        }
		// 檢查密碼格式是否符合
		if(!password.match(passwordPattern)){
			return res.status(400).json({
                message: "至少包括1個大寫字元、1個小寫字元、1個數字、1個特殊字元"
            });
		}
        // 檢查密碼是否一致
        if(password!==confirmPassword){
            return res.status(400).json({
                message: "密碼不一致"
            });
        }
        // 檢查帳號是否存在
        const existUser=await User.findOne({email});
        if(existUser){
            return res.status(400).json({
                message: "Email已存在"
            });
        }

        // 加密
        const salt=await bcrypt.genSalt();
        const passwordHash=await bcrypt.hash(password,salt);
        
        // 註冊
        const newUser=await User.create({username,email,password: passwordHash,createAt: dateTime(),updateAt: dateTime(),lastLoginAt: dateTime()});
		
        res.status(201).json({
            message: "註冊成功，請重新登入",
            user: {
                id: newUser._id,
                username: newUser.username,
                email: newUser.email,
                role: newUser.role
            }
        });
    }
    catch(err){
        res.status(500).json({
            message: err
        });
    }
};

// 登入
const login=async(req,res)=>{
    try{
        const {email,password}=req.body;
        const emailPattern=/^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        const passwordPattern=/^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,}$/;
		
        // 檢查全部欄位是否填寫
        if(!email || !password){
            return res.status(400).json({
                message: "請填寫完整"
            });
        }
        // 檢查Email格式是否符合
        if(!email.match(emailPattern)){
            return res.status(400).json({
                message: "Email格式錯誤"
            });
        }
        // 檢查密碼長度是否大於8個字元
        if(password.length<8){
			return res.status(400).json({
                message: "密碼8位以上"
            });
        }
		// 檢查密碼格式是否符合
		if(!password.match(passwordPattern)){
			return res.status(400).json({
                message: "至少包括1個大寫字元、1個小寫字元、1個數字、1個特殊字元"
            });
		}
        // 檢查帳號是否存在
        const user=await User.findOne({email});
        if(!user){
            return res.status(400).json({
                message: "Email不存在"
            });
        }
        // 比對密碼
        const checkPassword=await bcrypt.compare(password,user.password);
        if(!checkPassword){
            return res.status(400).json({
                message: "密碼錯誤"
            });
        }

        // 更新登入時間
        await User.findByIdAndUpdate(user._id,{lastLoginAt: dateTime()},{new: true});

        // JWT Token
        const token=jwt.sign({id: user._id},process.env.JWT_SECRET,{expiresIn: 60*60}); // 單位秒
        
        res.status(201).json({
            message: "登入成功",
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role
            },
			token
        });
    }
    catch(err){
        res.status(500).json({
            message: err
        });
    }
};

// 忘記密碼
const forgetPassword=async(req,res)=>{
    try{
        const {email}=req.body;
        const emailPattern=/^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

        // 檢查全部欄位是否填寫
        if(!email){
            return res.status(400).json({
                message: "請填寫完整"
            });
        }
        // 檢查Email格式是否符合
        if(!email.match(emailPattern)){
            return res.status(400).json({
                message: "Email格式錯誤"
            });
        }
        // 檢查帳號是否存在
        const user=await User.findOne({email});
        if(!user){
            return res.status(400).json({
                message: "此Email不存在"
            });
        }

        // JWT Token
        const resetToken=jwt.sign({id: user._id},process.env.JWT_FORGET_PASSWORD,{expiresIn: 10*60}); //10分鐘

        if(user && resetToken){
            let transporter=nodemailer.createTransport({
                service: "Gmail",
                auth:{
                    user: process.env.SEND_EMAIL,
                    pass: process.env.SEND_EMAIL_PASSWORD
                }
            });
    
            let mailOptions={
                from: "noreply@gmail.com",
                to: email,
                subject: "重設密碼",
                html: `
                    <p>請在10分鐘內點擊連結，重設密碼</p><br/>
                    <a href="http://localhost:3000/resetPassword/${resetToken}">點擊連結</a>
                `
            }
            await transporter.sendMail(mailOptions);
        }
        res.status(201).json({
            message: "請前往Email信箱，進行密碼重設"
        });
    }
    catch(err){
        res.status(500).json({
            message: "寄信權限不足"
        });
    }
};

// 重設密碼
const resetPassword=async(req,res)=>{
    try{
        const {resetToken,newPassword,confirmNewPassword}=req.body;
        const passwordPattern=/^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,}$/;
		
        // 檢查全部欄位是否填寫
        if(!resetToken || !newPassword || !confirmNewPassword){
            return res.status(400).json({
                message: "請填寫完整"
            });
        }
        // 檢查新密碼長度是否大於8個字元
        if(newPassword.length<8){
			return res.status(400).json({
                message: "密碼8位以上"
            });
        }
		// 檢查新密碼格式是否符合
		if(!newPassword.match(passwordPattern)){
			return res.status(400).json({
                message: "至少包括1個大寫字元、1個小寫字元、1個數字、1個特殊字元"
            });
		}
        // 檢查新密碼是否一致
        if(newPassword!==confirmNewPassword){
            return res.status(400).json({
                message: "密碼不一致"
            });
        }

        // Token Access
        const verify=jwt.verify(resetToken,process.env.JWT_FORGET_PASSWORD);
        if(!verify){
            return res.status(401).json({
                message: "已超過時間"
            });
        }

        // 檢查帳號是否存在
        const user=await User.findById(verify.id);
        if(!user){
            return res.status(400).json({
                message: "此Email不存在"
            });
        }

        // 加密
        const salt=await bcrypt.genSalt();
        const passwordHash=await bcrypt.hash(newPassword,salt);

        // 更新password
        await User.findByIdAndUpdate(user._id,{password: passwordHash,updateAt: dateTime()},{new: true});
        
        res.status(201).json({
            message: "密碼重設成功，請重新登入"
        });
    }
    catch(err){
        res.status(500).json({
            message: "無法重設密碼"
        });
    }
};

// 登出
const logout=(req,res)=>{
	res.status(201).json({
		message: "登出成功",
		user: {
			id: "",
			username: "",
			email: "",
			role: ""
		}
	});
};

// Check Login
const checkLogin=async(req,res)=>{
    try{
        res.status(201).json({
            user: {
                id: req.user._id,
                username: req.user.username,
                email: req.user.email,
				role: req.user.role
            }
        });
    }
    catch(err){
        res.status(500).json({
            message: err
        });
    }
};

module.exports={register,login,forgetPassword,resetPassword,logout,checkLogin};