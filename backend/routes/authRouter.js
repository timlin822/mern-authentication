const express=require("express");
const router=express.Router();

const checkAuth=require("../middleware/checkAuthMiddle");
const {register,login,forgetPassword,resetPassword,logout,checkLogin}=require("../controllers/authController");

router.post("/register",register);
router.post("/login",login);
router.post("/forgetPassword",forgetPassword);
router.post("/resetPassword",resetPassword);
router.get("/logout",logout);
router.get("/checkLogin",checkAuth,checkLogin);

module.exports=router;