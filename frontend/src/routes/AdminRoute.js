import {useContext} from 'react';
import {Navigate} from 'react-router-dom';

import UserContext from 'context/user/UserContext';

const AdminRoute=({children})=>{
	const {role}=useContext(UserContext);
	
    return role==="admin" ? children : <Navigate replace to="/login" />
}

export default AdminRoute;