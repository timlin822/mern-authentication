import {useState,useEffect,useContext} from 'react';
import {Link,Navigate,useNavigate} from 'react-router-dom';
import {FaUserAlt,FaLock,FaEye,FaEyeSlash} from 'react-icons/fa';

import MessageContext from 'context/message/MessageContext';
import UserContext from 'context/user/UserContext';

import Error from 'components/message/Error';
import Success from 'components/message/Success';
import Loading from 'components/message/Loading';

import './css/RegisterPage.css';

const RegisterPage=()=>{
	const navigate=useNavigate();

	const {error,success,loading,clearMessage,setError}=useContext(MessageContext);
	const {role,register}=useContext(UserContext);

	const [userData,setUserData]=useState({
		username: "",
		email: "",
		password: "",
		confirmPassword: ""
	});
	const {username,email,password,confirmPassword}=userData;
	const [passwordIsShow,setPasswordIsShow]=useState(false);
	const [confirmPasswordIsShow,setConfirmPasswordIsShow]=useState(false);

	useEffect(()=>{
		clearMessage();
	},[]);
	useEffect(()=>{
		if(success==="註冊成功，請重新登入"){
			setUserData({
				username: "",
				email: "",
				password: "",
				confirmPassword: ""
			});
			setTimeout(()=>{navigate("/login")},1000);
		}
	},[success]);

	const changeHandler=(e)=>{
		clearMessage();

		setUserData({
			...userData,
			[e.target.name]: e.target.value
		});
	};
	
	const passwordToggleHandler=()=>{
		setPasswordIsShow(!passwordIsShow);
	};
	const confirmPasswordToggleHandler=()=>{
		setConfirmPasswordIsShow(!confirmPasswordIsShow);
	};

	const submitHandler=(e)=>{
		e.preventDefault();
		const emailPattern=/^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        const passwordPattern=/^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,}$/;
        
        // 檢查全部欄位是否填寫
        if(!username || !email || !password || !confirmPassword){
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
        // 檢查密碼與確認密碼是否一致
        if(password!==confirmPassword){
			return setError("密碼不一致");
		}

		register({username,email,password,confirmPassword});
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
				<form className="register-form" onSubmit={submitHandler} noValidate>
					<h2 className="register-form-title">註冊</h2>
					{error && <Error error={error} />}
					{success && <Success success={success} />}
					{loading && <Loading />}
					<div className="input-group">
						<label htmlFor="username" className="input-group-icon label-icon"><FaUserAlt className="label-icon-cursor" /></label>
						<input type="text" className="input" id="username" name="username" placeholder="請輸入暱稱" autoComplete="off" value={username} onChange={changeHandler} />
					</div>
					<div className="input-group">
						<label htmlFor="email" className="input-group-icon label-icon"><FaUserAlt className="label-icon-cursor" /></label>
						<input type="email" className="input" id="email" name="email" placeholder="請輸入Email" autoComplete="off" value={email} onChange={changeHandler} />
					</div>
					<div className="input-group">
						<label htmlFor="password" className="input-group-icon label-icon"><FaLock className="label-icon-cursor" /></label>
						<input type={passwordIsShow?"text":"password"} className="input" id="password" name="password" placeholder="請輸入密碼" value={password} onChange={changeHandler} />
						<div className="input-group-icon eye-icon">{passwordIsShow?<FaEye className="eye-icon-cursor" onClick={passwordToggleHandler} />:<FaEyeSlash className="eye-icon-cursor" onClick={passwordToggleHandler} />}</div>
					</div>
					<div className="input-group">
						<label htmlFor="confirmPassword" className="input-group-icon label-icon"><FaLock className="label-icon-cursor" /></label>
						<input type={confirmPasswordIsShow?"text":"password"} className="input" id="confirmPassword" name="confirmPassword" placeholder="請再次輸入密碼" value={confirmPassword} onChange={changeHandler} />
						<div className="input-group-icon eye-icon">{confirmPasswordIsShow?<FaEye className="eye-icon-cursor" onClick={confirmPasswordToggleHandler} />:<FaEyeSlash className="eye-icon-cursor" onClick={confirmPasswordToggleHandler} />}</div>
					</div>
					<button type="submit" className="btn-register">註冊</button>
					<p className="text">已是會員? &nbsp;<Link to="/login" className="router-link">登入</Link></p>
				</form>
			</div>
		</section>
    );
}

export default RegisterPage;