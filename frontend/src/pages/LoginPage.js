import {useState,useEffect,useContext} from 'react';
import {Link,Navigate,useNavigate} from 'react-router-dom';
import {FaUserAlt,FaLock,FaEye,FaEyeSlash} from 'react-icons/fa';

import MessageContext from 'context/message/MessageContext';
import UserContext from 'context/user/UserContext';

import Error from 'components/message/Error';
import Loading from 'components/message/Loading';

import './css/LoginPage.css';

const LoginPage=()=>{
	const navigate=useNavigate();

	const {error,success,loading,clearMessage,setError}=useContext(MessageContext);
	const {role,login}=useContext(UserContext);

	const [userData,setUserData]=useState({
		email: localStorage.getItem("email") || "",
		password: "",
		rememberMe: JSON.parse(localStorage.getItem("rememberMe")) || false
	});
	const {email,password,rememberMe}=userData;
	const [passwordIsShow,setPasswordIsShow]=useState(false);

	useEffect(()=>{
		clearMessage();
	},[]);
	useEffect(()=>{
        if(rememberMe){
            localStorage.setItem("rememberMe",rememberMe);
            localStorage.setItem("email",email);
        }
        else{
            localStorage.removeItem("rememberMe");
            localStorage.removeItem("email");
        }
    },[email,rememberMe]);
	useEffect(()=>{
		if(success==="登入成功"){
			setUserData({
				email: localStorage.getItem("email") || "",
				password: "",
				rememberMe: JSON.parse(localStorage.getItem("rememberMe")) || false
			});
			if(role==="admin"){
				navigate("/admin");
			}
			else if(role==="dashboard"){
				navigate("/dashboard");
			}
			else if(role==="user"){
				navigate("/user");
			}
		}
	},[success]);

	const changeHandler=(e)=>{
		clearMessage();
		
		const value=e.target.type==="checkbox"?e.target.checked:e.target.value;
		setUserData({
			...userData,
			[e.target.name]: value
		});
	};
	
	const passwordToggleHandler=()=>{
		setPasswordIsShow(!passwordIsShow);
	};

	const submitHandler=(e)=>{
		e.preventDefault();
		const emailPattern=/^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        const passwordPattern=/^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,}$/;
		
		// 檢查全部欄位是否填寫
        if(!email || !password){
			return setError("請填寫完整");
        }
        // 檢查Email格式是否符合
        if(!email.match(emailPattern)){
			return setError("Email格式錯誤");
		}
		// 檢查密碼長度是否大於8個字元
        if(password.length<8){
			return setError("請填寫至少8個字元");
        }
		// 檢查密碼格式是否符合
		if(!password.match(passwordPattern)){
			return setError("請填寫至少包括1個大寫字元、1個小寫字元、1個數字、1個特殊字元");
		}
		
		login({email,password});
	};

	if(role==="admin"){
		return <Navigate replace to="/admin" />
	}
	else if(role==="dashboard"){
		return <Navigate replace to="/dashboard" />
	}
	else if(role==="user"){
		return <Navigate replace to="/user" />
	}

    return (
		<section className="section-padding bg-height">
			<div className="container container-padding">
				<form className="login-form" onSubmit={submitHandler} noValidate>
					<h2 className="login-form-title">登入</h2>
					{error && <Error error={error} />}
					{loading && <Loading />}
					<div className="input-group">
						<label htmlFor="email" className="input-group-icon label-icon"><FaUserAlt className="label-icon-cursor" /></label>
						<input type="email" className="input" id="email" name="email" placeholder="請輸入Email" autoComplete="off" value={email} onChange={changeHandler} />
					</div>
					<div className="input-group">
						<label htmlFor="password" className="input-group-icon label-icon"><FaLock className="label-icon-cursor" /></label>
						<input type={passwordIsShow?"text":"password"} className="input" id="password" name="password" placeholder="請輸入密碼" value={password} onChange={changeHandler} />
						<div className="input-group-icon eye-icon">{passwordIsShow?<FaEye className="eye-icon-cursor" onClick={passwordToggleHandler} />:<FaEyeSlash className="eye-icon-cursor" onClick={passwordToggleHandler} />}</div>
					</div>
					<div className="input-group space-between">
						<div><input type="checkbox" className="checkbox-input" id="rememberMe" name="rememberMe" checked={rememberMe} onChange={changeHandler} /><label htmlFor="rememberMe" className="rememberMe">記住我</label></div>
						<Link to="/forgetPassword" className="forget-password-link">忘記密碼</Link>
					</div>
					<button type="submit" className="btn-login">登入</button>
					<p className="text">不是會員? &nbsp;<Link to="/register" className="router-link">註冊</Link></p>
				</form>
			</div>
		</section>
    );
}

export default LoginPage;