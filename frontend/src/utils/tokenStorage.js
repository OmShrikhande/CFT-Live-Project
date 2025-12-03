const TOKEN_KEYS = {
  DASHBOARD_A: 'cft_token_dashboardA',
  DASHBOARD_B: 'cft_token_dashboardB',
  USER_A: 'cft_user_dashboardA',
  USER_B: 'cft_user_dashboardB',
};

const setToken = (dashboard, token) => {
  const key = dashboard === 'dashboardA' ? TOKEN_KEYS.DASHBOARD_A : TOKEN_KEYS.DASHBOARD_B;
  localStorage.setItem(key, token);
};

const getToken = (dashboard) => {
  const key = dashboard === 'dashboardA' ? TOKEN_KEYS.DASHBOARD_A : TOKEN_KEYS.DASHBOARD_B;
  return localStorage.getItem(key);
};

const removeToken = (dashboard) => {
  const key = dashboard === 'dashboardA' ? TOKEN_KEYS.DASHBOARD_A : TOKEN_KEYS.DASHBOARD_B;
  localStorage.removeItem(key);
};

const setUser = (dashboard, user) => {
  const key = dashboard === 'dashboardA' ? TOKEN_KEYS.USER_A : TOKEN_KEYS.USER_B;
  localStorage.setItem(key, JSON.stringify(user));
};

const getUser = (dashboard) => {
  const key = dashboard === 'dashboardA' ? TOKEN_KEYS.USER_A : TOKEN_KEYS.USER_B;
  const user = localStorage.getItem(key);
  return user ? JSON.parse(user) : null;
};

const removeUser = (dashboard) => {
  const key = dashboard === 'dashboardA' ? TOKEN_KEYS.USER_A : TOKEN_KEYS.USER_B;
  localStorage.removeItem(key);
};

const clearAll = (dashboard) => {
  removeToken(dashboard);
  removeUser(dashboard);
};

export { setToken, getToken, removeToken, setUser, getUser, removeUser, clearAll };
