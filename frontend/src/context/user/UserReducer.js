import {
    CHECK_LOGIN,REGISTER,LOGIN,LOGOUT,FORGET_PASSWORD,RESET_PASSWORD,
    CHECK_LOGIN_FAIL,REGISTER_FAIL,LOGIN_FAIL,FORGET_PASSWORD_FAIL,RESET_PASSWORD_FAIL
} from './UserType';

const UserReducer=(state,action)=>{
    switch (action.type){
        case CHECK_LOGIN:
        case LOGIN:
            return{
                ...state,
                role: action.payload.user.role,
                user: action.payload.user
            }
        case REGISTER:
		case FORGET_PASSWORD:
        case RESET_PASSWORD:
        case LOGOUT:
        case CHECK_LOGIN_FAIL:
        case REGISTER_FAIL:
        case LOGIN_FAIL:
        case FORGET_PASSWORD_FAIL:
		case RESET_PASSWORD_FAIL:
            return{
                ...state,
                role: "",
                user: {}
            }
        default:
            return state;
    }
};

export default UserReducer;