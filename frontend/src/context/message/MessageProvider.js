import {useEffect,useReducer} from 'react';

import MessageContext from './MessageContext';
import MessageReducer from './MessageReducer';
import {REQUEST,REQUEST_FINISH,CLEAR_MESSAGE,SET_ERROR,SET_SUCCESS} from './MessageType';

const MessageProvider=({children})=>{
    const initialState={
        loading: false,
        error: null,
        success: null
    };
    const [state,dispatch]=useReducer(MessageReducer,initialState);

    const setRequest=()=>{
        dispatch({
            type: REQUEST
        });
    };

    const setRequestFinish=()=>{
        dispatch({
            type: REQUEST_FINISH
        });
    };

    const clearMessage=()=>{
        dispatch({
            type: CLEAR_MESSAGE
        });
    };

    const setError=(error)=>{
        dispatch({
            type: SET_ERROR,
            payload: error
        });
    };

    const setSuccess=(success)=>{
        dispatch({
            type: SET_SUCCESS,
            payload: success
        });
    };

    useEffect(()=>{
        clearMessage();
    },[]);

    return(
        <MessageContext.Provider value={{
            loading: state.loading,
            error: state.error,
            success: state.success,
            setRequest,
            setRequestFinish,
            clearMessage,
            setError,
            setSuccess
        }}>
            {children}
        </MessageContext.Provider>
    );
};

export default MessageProvider;