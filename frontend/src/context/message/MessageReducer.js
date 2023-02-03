import {REQUEST,REQUEST_FINISH,CLEAR_MESSAGE,SET_ERROR,SET_SUCCESS} from './MessageType';

const MessageReducer=(state,action)=>{
    switch (action.type){
        case REQUEST:
            return{
                ...state,
                loading: true
            }
        case REQUEST_FINISH:
            return{
                ...state,
                loading: false
            }
        case CLEAR_MESSAGE:
            return{
                ...state,
                loading: false,
                error: null,
                success: null
            }
        case SET_ERROR:
            return{
                ...state,
                loading: false,
                error: action.payload,
                success: null
            }
        case SET_SUCCESS:
            return{
                ...state,
                loading: false,
                error: null,
                success: action.payload
            }
        default:
            return state;
    }
};

export default MessageReducer;