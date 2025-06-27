// Configuration for different environments
const config = {
  development: {
    API_URL: 'https://cmdb-backend-deployment-production.up.railway.app'
  },
  production: {
    API_URL: 'https://cmdb-backend-deployment-production.up.railway.app'
  }
};

const environment = import.meta.env.MODE || 'development';

export default config[environment]; 