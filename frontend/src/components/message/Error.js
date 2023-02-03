import {useContext} from 'react';
import {FaTimes} from 'react-icons/fa';

import MessageContext from 'context/message/MessageContext';

import './Message.css';

const Error=({error})=>{
    const {clearMessage}=useContext(MessageContext);

    const closeHandler=()=>{
        clearMessage();
	};

    return (
        <div className="message error">
            {error}
            <FaTimes className="message-close" onClick={closeHandler} />
        </div>
    );
}

export default Error;