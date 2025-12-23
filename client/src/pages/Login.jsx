import React from 'react';
import LoginForm from '../components/auth/LoginForm';

const Login = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 to-secondary-50 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      <div className="w-full max-w-md">
        {/* Background Pattern */}
        <div className="absolute inset-0 z-0">
          <div className="absolute inset-0 bg-gradient-to-br from-primary-400/20 to-secondary-400/20" />
          <div className="absolute inset-0" style={{
            backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.1'%3E%3Ccircle cx='30' cy='30' r='2'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`,
          }} />
        </div>

        {/* Login Form Container */}
        <div className="relative z-10">
          <LoginForm />
        </div>

        {/* Medical Background Icons */}
        <div className="absolute inset-0 z-0 overflow-hidden pointer-events-none">
          {/* Microscope Icon */}
          <div className="absolute top-10 left-10 opacity-10">
            <svg className="w-16 h-16 text-primary-600" fill="currentColor" viewBox="0 0 24 24">
              <path d="M9.5 8a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5zm0-4a1.5 1.5 0 1 1 0 3 1.5 1.5 0 0 1 0-3zM8 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zm0-1a3 3 0 1 1 0-6 3 3 0 0 1 0 6z"/>
              <path d="M9 16v-1h2v1a1 1 0 0 0 1 1h1v1h-1a2 2 0 0 1-2-2zM8 16v1a3 3 0 0 0 3 3h1v1h-1a4 4 0 0 1-4-4v-1h1z"/>
            </svg>
          </div>

          {/* Medical Cross */}
          <div className="absolute top-20 right-16 opacity-10">
            <svg className="w-12 h-12 text-secondary-600" fill="currentColor" viewBox="0 0 24 24">
              <path d="M11 2h2v7h7v2h-7v7h-2v-7H4v-2h7V2z"/>
            </svg>
          </div>

          {/* DNA Helix */}
          <div className="absolute bottom-16 left-16 opacity-10">
            <svg className="w-14 h-14 text-primary-600" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.94-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/>
            </svg>
          </div>

          {/* Lab Flask */}
          <div className="absolute bottom-10 right-10 opacity-10">
            <svg className="w-10 h-10 text-secondary-600" fill="currentColor" viewBox="0 0 24 24">
              <path d="M9 2v6.5L4.5 14a1 1 0 0 0 .86 1.5h13.28a1 1 0 0 0 .86-1.5L15 8.5V2H9zm1 1h4v5.5l3.5 5H6.5l3.5-5V3z"/>
              <circle cx="8" cy="11" r="1"/>
              <circle cx="16" cy="13" r="1"/>
            </svg>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;