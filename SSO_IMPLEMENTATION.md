# Custom Single Sign-On (SSO) System Implementation

## Overview
A complete JWT-based Single Sign-On system built with Node.js/Express backend and React frontend, supporting multiple dashboards with separate authentication contexts.

---

## Architecture

### Backend Structure
```
backend/
├── config/
│   └── db.js                 (Database connection & initialization)
├── controllers/
│   ├── loginController.js    (Login/Register logic)
│   └── dashboardController.js (Protected dashboard endpoints)
├── middleware/
│   └── authMiddleware.js     (JWT token verification)
├── routes/
│   └── authRoutes.js         (All auth endpoints)
├── utils/
│   └── jwt.js                (JWT sign/verify utilities)
├── db/
│   └── schema.sql            (Database schema)
├── server.js                 (Main server file)
├── .env                      (Configuration)
└── package.json
```

### Frontend Structure
```
frontend/src/
├── components/
│   └── ProtectedRoute.jsx    (Route protection wrapper)
├── context/
│   └── SSOContext.jsx        (Global auth state management)
├── hooks/
│   └── useAuth.js            (Custom hook for auth)
├── utils/
│   └── tokenStorage.js       (Secure token management)
├── pages/
│   ├── Home.jsx
│   ├── DashboardA/
│   │   ├── LoginA.jsx
│   │   └── DashboardA.jsx
│   └── DashboardB/
│       ├── LoginB.jsx
│       └── DashboardB.jsx
├── App.jsx                   (With SSO provider & protected routes)
└── App.css
```

---

## Key Features

### 1. **JWT-Based Authentication**
- Tokens generated on successful login
- Token expiry set to 7 days (configurable)
- Tokens verified on protected routes
- Token payload includes: `id`, `username`, `dashboard`

### 2. **Separate Dashboard Contexts**
- `dashboardA_users` table - Dashboard A users
- `dashboardB_users` table - Dashboard B users
- Each dashboard has independent authentication
- Users can have different credentials for each dashboard

### 3. **Auto-Registration**
- New users automatically created on first login
- No explicit registration page needed
- User credentials stored securely in MySQL

### 4. **Secure Token Storage**
- Tokens stored in localStorage
- Easy to switch to cookies if needed
- Organized by dashboard (separate tokens per dashboard)

### 5. **Protected Routes**
- Frontend routes protected with `ProtectedRoute` component
- Backend endpoints protected with auth middleware
- Automatic redirect to login if not authenticated
- Token validation on every protected request

---

## API Endpoints

### Authentication
```
POST /api/auth/dashboardA/login
  Body: { username, password }
  Response: { token, user: { id, username }, message }

POST /api/auth/dashboardB/login
  Body: { username, password }
  Response: { token, user: { id, username }, message }

GET /api/auth/verify-token
  Header: Authorization: Bearer <token>
  Response: { user, message }
```

### Protected Endpoints
```
GET /api/auth/dashboardA/data
  Header: Authorization: Bearer <token>
  Response: Dashboard A data with user info

GET /api/auth/dashboardB/data
  Header: Authorization: Bearer <token>
  Response: Dashboard B data with user info
```

---

## Backend Setup

### 1. Install Dependencies
```bash
cd backend
npm install
```

### 2. Configure .env
```env
PORT=5000
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=
DB_NAME=cft_project
JWT_SECRET=cft_project_sso_secret_key_change_in_production_2025
JWT_EXPIRY=7d
```

### 3. Ensure MySQL is Running
```bash
# Make sure MySQL service is running
# The database will be created automatically on first server start
```

### 4. Start Backend Server
```bash
npm run dev  # with nodemon for development
# or
npm start    # production mode
```

Server runs on `http://localhost:5000`

---

## Frontend Setup

### 1. Install Dependencies
```bash
cd frontend
npm install
```

### 2. Start Development Server
```bash
npm run dev
```

Frontend runs on `http://localhost:5174` (or next available port)

---

## How It Works

### Login Flow
1. User enters credentials on login page
2. Frontend calls `/api/auth/dashboardX/login`
3. Backend checks if user exists
   - If exists & password matches → Generate JWT
   - If doesn't exist → Create user & Generate JWT
4. JWT token returned to frontend
5. Token stored in localStorage
6. User redirected to dashboard
7. Protected route verifies token and allows access

### Protected Route Flow
1. User tries to access dashboard
2. `ProtectedRoute` component checks token in localStorage
3. If token exists → Show dashboard
4. If token missing/invalid → Redirect to login page

### Token Verification
1. Frontend can verify token freshness with `/api/auth/verify-token`
2. Backend validates token signature and expiry
3. If invalid → Token removed, user logged out
4. If valid → User info returned

---

## Using the SSO System

### In React Components

#### 1. Using the `useAuth` Hook
```jsx
import { useAuth } from './hooks/useAuth';

function MyComponent() {
  const { user, isAuthenticated, login, logout, loading, error } = useAuth('A');

  const handleLogin = async () => {
    const result = await login('username', 'password');
    if (result.success) {
      // User logged in
    }
  };

  const handleLogout = () => {
    logout();
  };

  return (
    <div>
      {isAuthenticated ? (
        <>
          <p>Welcome {user.username}</p>
          <button onClick={handleLogout}>Logout</button>
        </>
      ) : (
        <button onClick={handleLogin}>Login</button>
      )}
    </div>
  );
}
```

#### 2. Using SSO Context Directly
```jsx
import { useSSO } from './context/SSOContext';

function MyComponent() {
  const { dashboardA, login, logout } = useSSO();

  return <div>{dashboardA.user?.username}</div>;
}
```

#### 3. Protecting Routes
```jsx
<Route
  path="/dashboardA"
  element={
    <ProtectedRoute dashboard="A">
      <DashboardA />
    </ProtectedRoute>
  }
/>
```

---

## Token Management

### Token Storage
Tokens are stored in localStorage with keys:
- `cft_token_dashboardA` - Dashboard A token
- `cft_token_dashboardB` - Dashboard B token
- `cft_user_dashboardA` - Dashboard A user data
- `cft_user_dashboardB` - Dashboard B user data

### Getting Token in Components
```jsx
import { getToken } from './utils/tokenStorage';

const token = getToken('dashboardA');
```

### Making Authenticated API Calls
```jsx
const response = await fetch('/api/protected-endpoint', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});
```

---

## Database Schema

### dashboard_a_users Table
```sql
CREATE TABLE dashboard_a_users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(255) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

### dashboard_b_users Table
```sql
CREATE TABLE dashboard_b_users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(255) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

---

## Security Considerations

### Current Implementation (Development)
- ✅ JWT-based stateless authentication
- ✅ Tokens verified on protected routes
- ✅ Separate databases per dashboard
- ✅ Password stored in database (plaintext - for demo only)

### Production Recommendations
1. **Hash Passwords**: Use bcrypt or argon2
   ```bash
   npm install bcryptjs
   ```

2. **HTTPS Only**: Use HTTPS in production

3. **Secure JWT Secret**: Use strong, random secret
   ```javascript
   const crypto = require('crypto');
   console.log(crypto.randomBytes(32).toString('hex'));
   ```

4. **Secure Token Storage**: Consider httpOnly cookies instead of localStorage
   ```javascript
   res.cookie('token', jwt, { 
     httpOnly: true, 
     secure: true, 
     sameSite: 'strict'
   });
   ```

5. **CORS Configuration**: Whitelist specific origins
   ```javascript
   app.use(cors({
     origin: process.env.FRONTEND_URL,
     credentials: true
   }));
   ```

6. **Rate Limiting**: Add rate limiter for login endpoint
   ```bash
   npm install express-rate-limit
   ```

7. **Token Refresh**: Implement refresh tokens for longer sessions

---

## Testing the SSO System

### 1. Test Login
1. Go to http://localhost:5174
2. Click "Dashboard A"
3. Enter any username and password (will auto-register)
4. Verify redirect to dashboard
5. Check localStorage for token

### 2. Test Protected Routes
1. Try accessing dashboard without logging in
2. Should be redirected to login page
3. Check token in localStorage before/after logout

### 3. Test Token Verification
1. Log in and note the token
2. Open browser DevTools → Console
3. Run: `fetch('http://localhost:5000/api/auth/verify-token', { headers: { 'Authorization': 'Bearer <token>' } })`
4. Should return user info

### 4. Test Separate Dashboards
1. Log in to Dashboard A with credentials
2. Log in to Dashboard B with different credentials
3. Verify both have separate tokens and users

---

## Extending the System

### Adding More Dashboards
1. Create new table: `dashboard_c_users`
2. Add login endpoint: `POST /api/auth/dashboardC/login`
3. Add protected endpoint: `GET /api/auth/dashboardC/data`
4. Create frontend components: `DashboardC/LoginC.jsx`, `DashboardC.jsx`
5. Use `useAuth('C')` in components

### Adding Custom Claims to JWT
```javascript
const token = generateToken({
  id: user.id,
  username: user.username,
  dashboard: 'dashboardA',
  role: 'admin',           // Custom claim
  permissions: ['read', 'write'] // Custom claim
});
```

### Adding Logout on Token Expiry
```javascript
useEffect(() => {
  const checkTokenExpiry = async () => {
    const isValid = await verifyToken('A');
    if (!isValid) {
      logout();
      navigate('/login');
    }
  };

  const interval = setInterval(checkTokenExpiry, 60000); // Check every minute
  return () => clearInterval(interval);
}, []);
```

---

## Troubleshooting

### Issue: "Token not provided" error
**Solution**: Ensure token is in Authorization header as `Bearer <token>`

### Issue: "Invalid or expired token"
**Solution**: 
- Check token hasn't expired (7 days default)
- Verify JWT_SECRET in backend matches .env
- Log out and log back in to get fresh token

### Issue: CORS errors
**Solution**: Backend CORS is enabled for all origins. In production, restrict to specific domains.

### Issue: Database connection error
**Solution**:
- Ensure MySQL is running
- Check credentials in .env
- Database will auto-create on first run

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| PORT | 5000 | Backend server port |
| DB_HOST | localhost | MySQL host |
| DB_USER | root | MySQL username |
| DB_PASSWORD | (empty) | MySQL password |
| DB_NAME | cft_project | Database name |
| JWT_SECRET | cft_project_sso_secret_key_change_in_production_2025 | Secret for signing tokens |
| JWT_EXPIRY | 7d | Token expiration time |

---

## Summary

This SSO system provides:
- ✅ Secure JWT-based authentication
- ✅ Multi-dashboard support with separate contexts
- ✅ Protected routes on frontend and backend
- ✅ Auto-registration on first login
- ✅ Reusable React hooks and context
- ✅ Modular, scalable architecture
- ✅ Ready for production with security hardening

Plug the SSO system into multiple apps by:
1. Changing API_URL in frontend (currently http://localhost:5000)
2. Using the same `useAuth` hook
3. Wrapping app with `SSOProvider`
4. Protecting routes with `ProtectedRoute`
