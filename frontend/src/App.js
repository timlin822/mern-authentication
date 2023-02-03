import {BrowserRouter,Routes,Route,Navigate} from 'react-router-dom';

import MessageProvider from 'context/message/MessageProvider';
import UserProvider from 'context/user/UserProvider';

import HomePage from 'pages/HomePage';
import LoginPage from 'pages/LoginPage';
import RegisterPage from 'pages/RegisterPage';
import ForgetPasswordPage from 'pages/ForgetPasswordPage';
import ResetPasswordPage from 'pages/ResetPasswordPage';

import UserPage from 'pages/admin/UserPage';
import DashboardPage from 'pages/admin/DashboardPage';
import AdminPage from 'pages/admin/AdminPage';

import Navbar from 'components/navbar/Navbar';
import Footer from 'components/footer/Footer';

import UserRoute from 'routes/UserRoute';
import DashboardRoute from 'routes/DashboardRoute';
import AdminRoute from 'routes/AdminRoute';

import './App.css';

function App() {
  return (
    <MessageProvider>
    <UserProvider>
      <BrowserRouter>
        <Navbar />
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/forgetPassword" element={<ForgetPasswordPage />} />
          <Route path="/resetPassword/:resetToken" element={<ResetPasswordPage />} />

          <Route path="/user" element={<UserRoute><UserPage /></UserRoute>} />
          <Route path="/dashboard" element={<DashboardRoute><DashboardPage /></DashboardRoute>} />
          <Route path="/admin" element={<AdminRoute><AdminPage /></AdminRoute>} />

          <Route path="*" element={<Navigate replace to="/" />} />
        </Routes>
        <Footer />
      </BrowserRouter>
    </UserProvider>
    </MessageProvider>
  );
}

export default App;