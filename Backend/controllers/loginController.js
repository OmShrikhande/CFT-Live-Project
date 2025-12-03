const { pool } = require('../config/db');
const { generateToken } = require('../utils/jwt');

const loginDashboardA = async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const connection = await pool.getConnection();

    const [users] = await connection.query(
      'SELECT * FROM dashboard_a_users WHERE username = ?',
      [username]
    );

    if (users.length > 0) {
      const user = users[0];
      if (user.password === password) {
        const token = generateToken({
          id: user.id,
          username: user.username,
          dashboard: 'dashboardA',
        });
        connection.release();
        return res.status(200).json({
          success: true,
          message: 'Login successful',
          token,
          user: { id: user.id, username: user.username },
        });
      } else {
        connection.release();
        return res.status(401).json({ error: 'Invalid password' });
      }
    } else {
      await connection.query(
        'INSERT INTO dashboard_a_users (username, password) VALUES (?, ?)',
        [username, password]
      );
      const [newUser] = await connection.query(
        'SELECT * FROM dashboard_a_users WHERE username = ?',
        [username]
      );
      const token = generateToken({
        id: newUser[0].id,
        username: newUser[0].username,
        dashboard: 'dashboardA',
      });
      connection.release();
      return res.status(201).json({
        success: true,
        message: 'User created and logged in successfully',
        token,
        user: { id: newUser[0].id, username: newUser[0].username },
      });
    }
  } catch (error) {
    console.error('Error in loginDashboardA:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

const loginDashboardB = async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const connection = await pool.getConnection();

    const [users] = await connection.query(
      'SELECT * FROM dashboard_b_users WHERE username = ?',
      [username]
    );

    if (users.length > 0) {
      const user = users[0];
      if (user.password === password) {
        const token = generateToken({
          id: user.id,
          username: user.username,
          dashboard: 'dashboardB',
        });
        connection.release();
        return res.status(200).json({
          success: true,
          message: 'Login successful',
          token,
          user: { id: user.id, username: user.username },
        });
      } else {
        connection.release();
        return res.status(401).json({ error: 'Invalid password' });
      }
    } else {
      await connection.query(
        'INSERT INTO dashboard_b_users (username, password) VALUES (?, ?)',
        [username, password]
      );
      const [newUser] = await connection.query(
        'SELECT * FROM dashboard_b_users WHERE username = ?',
        [username]
      );
      const token = generateToken({
        id: newUser[0].id,
        username: newUser[0].username,
        dashboard: 'dashboardB',
      });
      connection.release();
      return res.status(201).json({
        success: true,
        message: 'User created and logged in successfully',
        token,
        user: { id: newUser[0].id, username: newUser[0].username },
      });
    }
  } catch (error) {
    console.error('Error in loginDashboardB:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

module.exports = { loginDashboardA, loginDashboardB };
