# JWT Authentication Express API

A complete JWT authentication system built with Express.js, featuring secure user registration, login, token refresh, and role-based access control.

## Features

- 🔐 **Secure Authentication**: JWT-based authentication with access and refresh tokens
- 👤 **User Management**: Registration, login, profile management
- 🛡️ **Security**: Password hashing with bcrypt, rate limiting, CORS
- 🎯 **Role-based Access**: Admin routes and permission system
- 📊 **Health Monitoring**: Built-in health checks and monitoring
- 🔄 **Token Management**: Automatic token refresh and logout functionality

## Quick Start

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Set up environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start the server:**
   ```bash
   npm start
   ```

4. **For development:**
   ```bash
   npm run dev
   ```

## API Endpoints

### Public Endpoints
- `GET /` - API information
- `GET /health` - Health check
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/refresh` - Token refresh

### Protected Endpoints (require authentication)
- `GET /api/auth/profile` - Get user profile
- `POST /api/auth/logout` - Logout (invalidate tokens)
- `GET /api/protected` - Protected route example

### Admin Endpoints (require admin role)
- `GET /api/admin` - Admin dashboard with user statistics

## Authentication Flow

1. **Registration:**
   ```bash
   POST /api/auth/register
   {
     "username": "johndoe",
     "email": "john@example.com",
     "password": "securepassword123",
     "firstName": "John",
     "lastName": "Doe"
   }
   ```

2. **Login:**
   ```bash
   POST /api/auth/login
   {
     "username": "johndoe",
     "password": "securepassword123"
   }
   ```

3. **Access protected routes:**
   ```bash
   GET /api/protected
   Headers: Authorization: Bearer <access_token>
   ```

4. **Refresh token:**
   ```bash
   POST /api/auth/refresh
   {
     "refreshToken": "<refresh_token>"
   }
   ```

## Configuration

### Environment Variables
```env
# Server Configuration
PORT=3000
NODE_ENV=development

# JWT Configuration
JWT_SECRET=your_super_secret_jwt_key_here
REFRESH_SECRET=your_super_secret_refresh_key_here
ACCESS_TOKEN_EXPIRES_IN=15m
REFRESH_TOKEN_EXPIRES_IN=7d

# Security
RATE_LIMIT_MAX_REQUESTS=10
RATE_LIMIT_WINDOW_MS=900000
PASSWORD_MIN_LENGTH=6
BCRYPT_SALT_ROUNDS=12
```

### Security Features

- **Password Hashing**: bcrypt with 12 salt rounds
- **Rate Limiting**: 10 attempts per 15 minutes for auth endpoints
- **CORS**: Configurable origin restrictions
- **Helmet**: Security headers
- **Input Validation**: Joi schema validation
- **Token Expiration**: Short-lived access tokens (15min) with refresh capability

## Project Structure

```
jwt-auth-express/
├── app.js              # Main application file
├── .env.example        # Environment variables template
├── README.md          # This file
└── package.json       # Dependencies and scripts
```

## Development

### Adding New Routes

1. **Public routes**: Add directly to app.js
2. **Protected routes**: Use `authenticateToken` middleware
3. **Admin routes**: Use both `authenticateToken` and `requireRole('admin')` middlewares

### Middleware Examples

```javascript
// Authentication required
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'Protected data', user: req.user });
});

// Admin role required
app.get('/admin', authenticateToken, requireRole('admin'), (req, res) => {
  res.json({ message: 'Admin data', users: getAllUsers() });
});
```

### Error Handling

The API includes comprehensive error handling:
- 400: Bad Request (validation errors)
- 401: Unauthorized (invalid/expired tokens)
- 403: Forbidden (insufficient permissions)
- 404: Not Found
- 409: Conflict (user already exists)
- 500: Internal Server Error

## Security Best Practices

### Password Security
- Minimum 6 characters
- bcrypt hashing with salt rounds
- No plaintext storage
- Failed login attempt tracking

### Token Security
- Short-lived access tokens (15 minutes)
- Long-lived refresh tokens (7 days)
- Separate secrets for access and refresh tokens
- Token blacklisting on logout

### Rate Limiting
- Auth endpoints: 10 attempts per 15 minutes
- Configurable limits
- IP-based tracking

### CORS Configuration
- Configurable allowed origins
- Credentials support
- Secure cookie settings

## Production Deployment

1. **Environment Setup:**
   ```bash
   NODE_ENV=production
   JWT_SECRET=your_production_secret
   REFRESH_SECRET=your_production_refresh_secret
   ```

2. **Security Headers:**
   - HTTPS only
   - Secure cookies
   - HSTS headers

3. **Database Integration:**
   - Replace in-memory storage with MongoDB/PostgreSQL
   - Add user sessions table
   - Implement token blacklisting

4. **Monitoring:**
   - Add logging to external service
   - Health check endpoints
   - Metrics collection

## Testing

```bash
# Run tests
npm test

# Run linting
npm run lint

# Run in development mode
npm run dev
```

## API Response Examples

### Successful Registration
```json
{
  "message": "User registered successfully",
  "user": {
    "id": 1,
    "username": "johndoe",
    "email": "john@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "createdAt": "2024-01-01T00:00:00.000Z"
  },
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Protected Route Response
```json
{
  "message": "This is a protected route",
  "user": {
    "userId": 1,
    "username": "johndoe",
    "email": "john@example.com"
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

## License

MIT

## Support

For issues and questions:
- Documentation: [JWT.io](https://jwt.io/)
- Express.js: [expressjs.com](https://expressjs.com/)
- Security: [OWASP JWT Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
