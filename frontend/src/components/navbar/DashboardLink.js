import {Link} from 'react-router-dom';

import './Navbar.css';

const DashboardLink=({navbarCloseHandler,logoutHandler})=>{
    return (
		<>
			<Link to="/" className="btn-link" onClick={navbarCloseHandler}>首頁</Link>
			<Link to="/dashboard" className="btn-link" onClick={navbarCloseHandler}>Dashboard</Link>
			<Link to="/user" className="btn-link" onClick={navbarCloseHandler}>User</Link>
			<div className="btn-link-login" onClick={logoutHandler}>登出</div>
		</>
    );
}

export default DashboardLink;