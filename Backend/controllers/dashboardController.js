const getDashboardA = (req, res) => {
  try {
    const user = req.user;
    res.status(200).json({
      success: true,
      message: 'Welcome to Dashboard A',
      user,
      dashboardData: {
        name: 'Dashboard A',
        description: 'This is Dashboard A',
      },
    });
  } catch (error) {
    console.error('Error in getDashboardA:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

const getDashboardB = (req, res) => {
  try {
    const user = req.user;
    res.status(200).json({
      success: true,
      message: 'Welcome to Dashboard B',
      user,
      dashboardData: {
        name: 'Dashboard B',
        description: 'This is Dashboard B',
      },
    });
  } catch (error) {
    console.error('Error in getDashboardB:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

module.exports = { getDashboardA, getDashboardB };
