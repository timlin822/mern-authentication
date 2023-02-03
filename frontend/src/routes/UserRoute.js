import {useContext} from 'react';
import {Navigate} from 'react-router-dom';

import UserContext from 'context/user/UserContext';

const UserRoute=({children})=>{
    const {role}=useContext(UserContext);
	
    return (role==="admin" || role==="dashboard" || role==="user") ? children : <Navigate replace to="/login" />
}

export default UserRoute;