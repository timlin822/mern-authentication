import {useContext} from 'react';
import {FaTimes} from 'react-icons/fa';

import MessageContext from 'context/message/MessageContext';

import './Message.css';

const Success=({success})=>{
    const {clearMessage}=useContext(MessageContext);

    const closeHandler=()=>{
        clearMessage();
	};

    return (
        <div className="message success">
            {success}
            <FaTimes className="message-close" onClick={closeHandler} />
        </div>
    );
}

export default Success;