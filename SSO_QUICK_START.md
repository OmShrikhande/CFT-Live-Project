# SSO System - Quick Start Guide

## 🚀 Quick Setup (5 Minutes)

### Prerequisites
- Node.js installed
- MySQL running
- Port 5000 and 5174 available

### Step 1: Backend Setup
```bash
cd backend
npm install
npm run dev
```
✅ Server running on http://localhost:5000

### Step 2: Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
✅ App running on http://localhost:5174

### Step 3: Test It
1. Open http://localhost:5174
2. Click "Dashboard A"
3. Enter any username/password
4. Get redirected to dashboard ✅

---

## 📦 Integration into New Projects

### For New Dashboard/App

#### 1. Copy These Files to Your React App
```
src/
├── context/SSOContext.jsx
├── hooks/useAuth.js
├── components/ProtectedRoute.jsx
└── utils/tokenStorage.js
```

#### 2. Wrap Your App with SSOProvider
```jsx
// App.jsx
import { SSOProvider } from './context/SSOContext';

function App() {
  return (
    <SSOProvider>
      {/* Your routes */}
    </SSOProvider>
  );
}
```

#### 3. Protect Your Routes
```jsx
import { ProtectedRoute } from './components/ProtectedRoute';

<Route
  path="/dashboard"
  element={
    <ProtectedRoute dashboard="A">
      <YourDashboard />
    </ProtectedRoute>
  }
/>
```

#### 4. Use Authentication in Components
```jsx
import { useAuth } from './hooks/useAuth';

function MyComponent() {
  const { user, isAuthenticated, login, logout } = useAuth('A');

  return (
    <div>
      {isAuthenticated && <p>Welcome {user.username}</p>}
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

---

## 🔐 Implementation Checklist

### Backend
- [x] JWT utilities (sign/verify)
- [x] Auth middleware
- [x] Login endpoints (Dashboard A/B)
- [x] Protected endpoints
- [x] Database setup
- [x] Error handling

### Frontend
- [x] SSO Context
- [x] useAuth hook
- [x] ProtectedRoute component
- [x] Token storage utility
- [x] Login pages
- [x] Dashboard pages

---

## 📝 Code Examples

### Example 1: Simple Login Page
```jsx
import { useAuth } from './hooks/useAuth';
import { useNavigate } from 'react-router-dom';

function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const { login, loading, error } = useAuth('A');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    const result = await login(username, password);
    if (result.success) navigate('/dashboard');
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        placeholder="Username"
      />
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Password"
      />
      <button disabled={loading}>{loading ? 'Loading...' : 'Login'}</button>
      {error && <p>{error}</p>}
    </form>
  );
}
```

### Example 2: Protected Dashboard
```jsx
import { useAuth } from './hooks/useAuth';
import { useNavigate } from 'react-router-dom';

function Dashboard() {
  const { user, logout } = useAuth('A');
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  return (
    <div>
      <h1>Dashboard</h1>
      <p>Welcome {user?.username}</p>
      <button onClick={handleLogout}>Logout</button>
    </div>
  );
}
```

### Example 3: Multiple Dashboards
```jsx
function App() {
  return (
    <SSOProvider>
      <Router>
        <Routes>
          <Route path="/login/a" element={<LoginA />} />
          <Route
            path="/dashboard/a"
            element={
              <ProtectedRoute dashboard="A">
                <DashboardA />
              </ProtectedRoute>
            }
          />

          <Route path="/login/b" element={<LoginB />} />
          <Route
            path="/dashboard/b"
            element={
              <ProtectedRoute dashboard="B">
                <DashboardB />
              </ProtectedRoute>
            }
          />

          <Route path="/login/c" element={<LoginC />} />
          <Route
            path="/dashboard/c"
            element={
              <ProtectedRoute dashboard="C">
                <DashboardC />
              </ProtectedRoute>
            }
          />
        </Routes>
      </Router>
    </SSOProvider>
  );
}
```

### Example 4: API Calls with Token
```jsx
import { useAuth } from './hooks/useAuth';

function DataComponent() {
  const { getToken, user } = useAuth('A');
  const [data, setData] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      const token = getToken();
      const response = await fetch('/api/protected-data', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      const result = await response.json();
      setData(result);
    };

    fetchData();
  }, [user]);

  return <div>{JSON.stringify(data)}</div>;
}
```

---

## 🛠️ Customization

### Change API URL
In `SSOContext.jsx`, update:
```javascript
const API_URL = 'http://your-backend-url:5000/api/auth';
```

### Change Token Expiry
In backend `.env`:
```env
JWT_EXPIRY=30d  // Change from 7d
```

### Change Token Storage Method
In `tokenStorage.js`, replace localStorage with cookies:
```javascript
const setToken = (dashboard, token) => {
  document.cookie = `token_${dashboard}=${token}`;
};
```

### Add More Dashboards
1. Backend: Add new table and endpoint
2. Frontend: Use `useAuth('C')` for Dashboard C

---

## 🔍 Debugging

### Check Token
```javascript
// In browser console
localStorage.getItem('cft_token_dashboardA')
```

### Verify Token
```javascript
// In browser console
fetch('http://localhost:5000/api/auth/verify-token', {
  headers: {
    'Authorization': `Bearer ${localStorage.getItem('cft_token_dashboardA')}`
  }
}).then(r => r.json()).then(console.log)
```

### Check Auth State
```javascript
// In component
import { useSSO } from './context/SSOContext';
const { dashboardA } = useSSO();
console.log(dashboardA);
```

---

## 📊 Request/Response Examples

### Login Request
```bash
curl -X POST http://localhost:5000/api/auth/dashboardA/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"pass1"}'
```

### Login Response
```json
{
  "success": true,
  "message": "User created and logged in successfully",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "user1"
  }
}
```

### Protected Endpoint Request
```bash
curl -X GET http://localhost:5000/api/auth/dashboardA/data \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Protected Endpoint Response
```json
{
  "success": true,
  "message": "Welcome to Dashboard A",
  "user": {
    "id": 1,
    "username": "user1",
    "dashboard": "dashboardA"
  },
  "dashboardData": {
    "name": "Dashboard A",
    "description": "This is Dashboard A"
  }
}
```

---

## 🚨 Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| Tokens not persisting | Check localStorage in DevTools → Application |
| CORS error | Backend has CORS enabled by default |
| 401 Unauthorized | Token missing or expired, log in again |
| Database error | Ensure MySQL running, check .env credentials |
| Token verification fails | Check JWT_SECRET matches between sign/verify |

---

## 📚 File Reference

| File | Purpose | Key Function |
|------|---------|--------------|
| `SSOContext.jsx` | Global auth state | `useSSO()` |
| `useAuth.js` | Auth hook | `useAuth('A')` |
| `ProtectedRoute.jsx` | Route protection | Wraps routes |
| `tokenStorage.js` | Token management | `setToken()`, `getToken()` |
| `authMiddleware.js` | Backend protection | `authMiddleware` |
| `jwt.js` | Token operations | `generateToken()`, `verifyToken()` |

---

## 🎯 Next Steps

1. **Test the system**: Login, logout, refresh
2. **Customize**: Adjust colors, add features
3. **Secure**: Hash passwords in production
4. **Scale**: Add refresh tokens, rate limiting
5. **Monitor**: Add logging and analytics

---

## ✅ Verification Checklist

- [x] Backend running on port 5000
- [x] Frontend running on port 5174
- [x] MySQL database created and tables initialized
- [x] Can login to Dashboard A
- [x] Can login to Dashboard B with different user
- [x] Tokens stored in localStorage
- [x] Protected routes redirect to login
- [x] Logout clears tokens
- [x] Token verification works
- [x] Can make authenticated API calls

---

## 📞 Support

For issues or questions:
1. Check browser console for errors
2. Check backend logs: `npm run dev`
3. Verify .env configuration
4. Ensure MySQL is running
5. Check network tab in DevTools for API responses
