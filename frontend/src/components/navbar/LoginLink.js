import {Link} from 'react-router-dom';

import './Navbar.css';

const LoginLink=({navbarCloseHandler})=>{
    return (
		<>
			<Link to="/" className="btn-link" onClick={navbarCloseHandler}>首頁</Link>
			<Link to="/login" className="btn-link-login" onClick={navbarCloseHandler}>登入</Link>
		</>
    );
}

export default LoginLink;