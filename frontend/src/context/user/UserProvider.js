import {useEffect,useContext,useReducer} from 'react';
import axios from 'axios';
import Cookies from 'js-cookie';

import UserContext from './UserContext';
import UserReducer from './UserReducer';
import {
    CHECK_LOGIN,REGISTER,LOGIN,LOGOUT,FORGET_PASSWORD,RESET_PASSWORD,
    CHECK_LOGIN_FAIL,REGISTER_FAIL,LOGIN_FAIL,FORGET_PASSWORD_FAIL,RESET_PASSWORD_FAIL
} from './UserType';

import MessageContext from 'context/message/MessageContext';

const UserProvider=({children})=>{
    const {setRequest,setRequestFinish,setError,setSuccess}=useContext(MessageContext);

    const initialState={
        role: "",
        user: {}
    };
    const [state,dispatch]=useReducer(UserReducer,initialState);

	const checkLogin=async(token)=>{
        try{
            const res=await axios.get("/api/auth/checkLogin",{
                headers: {
                    Authorization: `Bearer ${token}`
                }
            });
            dispatch({
                type: CHECK_LOGIN,
                payload: res.data
            });
        }
        catch(err){
            dispatch({
                type: CHECK_LOGIN_FAIL
            });
        }
    };
	
    const register=async(newUser)=>{
        try{
            setRequest();
            const res=await axios.post("/api/auth/register",newUser);
            setRequestFinish();
            setSuccess(res.data.message);
            dispatch({
                type: REGISTER
            });
        }
        catch(err){
            setRequestFinish();
            setError(err.response.data.message);
            dispatch({
                type: REGISTER_FAIL
            });
        }
    };

    const login=async(user)=>{
        try{
            setRequest();
            const res=await axios.post("/api/auth/login",user);
            setRequestFinish();
            Cookies.set("token",res.data.token,{
				expires: (1/1440)*60, //60分鐘
                secure: process.env.REACT_APP_NODE_ENV!=="development",
                sameSite: "Lax"
			});
            setSuccess(res.data.message);
			dispatch({
                type: LOGIN,
                payload: res.data
            });
        }
        catch(err){
            setRequestFinish();
            setError(err.response.data.message);
            dispatch({
                type: LOGIN_FAIL
            });
        }
    };

    const logout=()=>{
        Cookies.remove("token");
        dispatch({
            type: LOGOUT
        });
    };

    const forgetPassword=async(email)=>{
        try{
            setRequest();
            const res=await axios.post("/api/auth/forgetPassword",{email});
            setRequestFinish();
            setSuccess(res.data.message);
            dispatch({
                type: FORGET_PASSWORD
            });
            Cookies.set("isResetPassword",true,{expires: (1/1440)*10}); //10分鐘
        }
        catch(err){
            setRequestFinish();
            setError(err.response.data.message);
            dispatch({
                type: FORGET_PASSWORD_FAIL
            });
        }
    };

    const resetPassword=async(newResetPassword)=>{
        try{
            setRequest();
            const res=await axios.post("/api/auth/resetPassword",newResetPassword);
            setRequestFinish();
            setSuccess(res.data.message);
            dispatch({
                type: RESET_PASSWORD
            });
            Cookies.remove("isResetPassword");
        }
        catch(err){
            setRequestFinish();
            setError(err.response.data.message);
            dispatch({
                type: RESET_PASSWORD_FAIL
            });
        }
    };

    useEffect(()=>{
        const token=Cookies.get("token") || "";

		if(token){
			checkLogin(token);
		}
	},[]);

    return(
        <UserContext.Provider value={{
            role: state.role,
            user: state.user,
            register,
            login,
            logout,
			forgetPassword,
			resetPassword
        }}>
            {children}
        </UserContext.Provider>
    );
};

export default UserProvider;