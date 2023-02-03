import {useState,useEffect,useContext} from 'react';
import {Navigate,useNavigate} from 'react-router-dom';
import {FaUserAlt} from 'react-icons/fa';

import MessageContext from 'context/message/MessageContext';
import UserContext from 'context/user/UserContext';

import Error from 'components/message/Error';
import Success from 'components/message/Success';
import Loading from 'components/message/Loading';

import './css/ForgetPasswordPage.css';

const ForgetPasswordPage=()=>{
	const navigate=useNavigate();

	const {error,success,loading,clearMessage,setError}=useContext(MessageContext);
	const {role,forgetPassword}=useContext(UserContext);

	const [email,setEmail]=useState("");

	useEffect(()=>{
		clearMessage();
	},[]);
    useEffect(()=>{
		if(success==="請前往Email信箱，進行密碼重設"){
			setEmail("");
			setTimeout(()=>{navigate("/login")},5000);
		}
	},[success]);

	const changeHandler=(e)=>{
		clearMessage();

        setEmail(e.target.value);
	};

	const submitHandler=(e)=>{
		e.preventDefault();
		const emailPattern=/^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        
		// 檢查全部欄位是否填寫
        if(!email){
			return setError("請填寫完整");
        }
        // 檢查Email格式是否符合
        if(!email.match(emailPattern)){
			return setError("Email格式錯誤");
		}

		forgetPassword(email);
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
				<form className="forget-password-form" onSubmit={submitHandler} noValidate>
					<h2 className="forget-password-form-title">忘記密碼</h2>
					{error && <Error error={error} />}
					{success && <Success success={success} />}
					{loading && <Loading />}
					<div className="input-group">
						<label htmlFor="email" className="label-icon"><FaUserAlt className="icon-cursor" /></label>
						<input type="email" className="input" id="email" name="email" placeholder="請輸入Email" autoComplete="off" value={email} onChange={changeHandler} />
					</div>
					<button type="submit" className="btn-submit">送出</button>
				</form>
			</div>
		</section>
    );
}

export default ForgetPasswordPage;