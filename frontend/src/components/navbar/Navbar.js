import {useState,useContext} from 'react';
import {Link,useNavigate} from 'react-router-dom';
import {FaTimes,FaBars} from 'react-icons/fa';

import UserContext from 'context/user/UserContext';

import AdminLink from './AdminLink';
import DashboardLink from './DashboardLink';
import UserLink from './UserLink';
import LoginLink from './LoginLink';

import logo from 'images/logo.png';

import './Navbar.css';

const Navbar=()=>{
    const navigate=useNavigate();

    const {role,logout}=useContext(UserContext);
    
    const [navbarIsOpen,setNavbarIsOpen]=useState(false);

	const navbarClickHandler=()=>{
		setNavbarIsOpen(!navbarIsOpen);
	};
	const navbarCloseHandler=()=>{
		setNavbarIsOpen(false);
	};
	
	const logoutHandler=()=>{
		logout();
		navbarCloseHandler();
		navigate("/");
	};

    return (
        <header className="navbar">
            <nav className="container navbar-menu">
                <Link to="/" className="navbar-logo" onClick={navbarCloseHandler}><img src={logo} alt="logo" /></Link>
                <div className={navbarIsOpen?"main-navbar main-navbar-open":"main-navbar"}>
                    {role==="admin" && <AdminLink navbarCloseHandler={navbarCloseHandler} logoutHandler={logoutHandler} />}
                    {role==="dashboard" && <DashboardLink navbarCloseHandler={navbarCloseHandler} logoutHandler={logoutHandler} />}
                    {role==="user" && <UserLink navbarCloseHandler={navbarCloseHandler} logoutHandler={logoutHandler} />}
                    {!role && <LoginLink navbarCloseHandler={navbarCloseHandler} />}
                </div>
                {navbarIsOpen?<FaTimes className="btn-toggle" onClick={navbarClickHandler} />:<FaBars className="btn-toggle" onClick={navbarClickHandler} />}
            </nav>
        </header>
    );
}

export default Navbar;