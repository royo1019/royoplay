// Configuration for different environments
const config = {
  development: {
    API_URL: 'http://localhost:5000'
  },
  production: {
    // TODO: Replace this URL with your actual deployed backend URL
    API_URL: 'https://your-cmdb-analyzer-backend.railway.app'
  }
};

const environment = import.meta.env.MODE || 'development';

export default config[environment]; 