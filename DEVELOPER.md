# Developer Documentation - ZenEyer Auth

## Integrating with React (Headless)

This plugin is designed to work seamlessly with React. Below is a "Copy & Paste" implementation guide.

### 1. Google OAuth Setup

We recommend using `@react-oauth/google` for the frontend logic.

```bash
npm install @react-oauth/google

Configure your main.tsx or App.tsx:

TypeScript

import { GoogleOAuthProvider } from '@react-oauth/google';

<GoogleOAuthProvider clientId="YOUR_GOOGLE_CLIENT_ID">
  <App />
</GoogleOAuthProvider>
2. The Login Component
Here is a modern React component that handles both Email/Password and Google Login.

TypeScript

import React, { useState } from 'react';
import { GoogleLogin } from '@react-oauth/google';

const Login = () => {
  const [status, setStatus] = useState('idle');

  // --- 1. Email/Password Login ---
  const handleEmailLogin = async (e) => {
    e.preventDefault();
    const email = e.target.email.value;
    const password = e.target.password.value;

    const res = await fetch('[https://yoursite.com/wp-json/zeneyer/v1/auth/login](https://yoursite.com/wp-json/zeneyer/v1/auth/login)', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    
    const data = await res.json();
    if (data.success) {
      saveToken(data.data.token);
    }
  };

  // --- 2. Google Login Handler ---
  const handleGoogleSuccess = async (credentialResponse) => {
    setStatus('loading');
    
    // Send the Google ID Token to WordPress
    const res = await fetch('[https://yoursite.com/wp-json/zeneyer/v1/auth/google](https://yoursite.com/wp-json/zeneyer/v1/auth/google)', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        id_token: credentialResponse.credential 
      })
    });

    const data = await res.json();
    
    if (data.success) {
      console.log("Logged in as:", data.data.user.display_name);
      saveToken(data.data.token); // Save your WP JWT
      setStatus('success');
    } else {
      setStatus('error');
    }
  };

  const saveToken = (token) => {
    localStorage.setItem('zen_jwt', token);
    // Redirect user...
  };

  return (
    <div className="login-container">
      {/* Google Button */}
      <div className="google-btn">
        <GoogleLogin
          onSuccess={handleGoogleSuccess}
          onError={() => console.log('Login Failed')}
          useOneTap
        />
      </div>

      <div className="divider">OR</div>

      {/* Standard Form */}
      <form onSubmit={handleEmailLogin}>
        <input name="email" type="email" placeholder="Email" required />
        <input name="password" type="password" placeholder="Password" required />
        <button type="submit">Log In</button>
      </form>
    </div>
  );
};

export default Login;
3. Making Authenticated Requests
Once you have the token, include it in the Authorization header.

JavaScript

const getProfile = async () => {
  const token = localStorage.getItem('zen_jwt');
  
  const res = await fetch('[https://yoursite.com/wp-json/wp/v2/users/me](https://yoursite.com/wp-json/wp/v2/users/me)', {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  const user = await res.json();
  return user;
};

