import {useContext} from 'react';
import {Navigate} from 'react-router-dom';

import UserContext from 'context/user/UserContext';

const DashboardRoute=({children})=>{
	const {role}=useContext(UserContext);
	
    return (role==="admin" || role==="dashboard") ? children : <Navigate replace to="/login" />
}

export default DashboardRoute;