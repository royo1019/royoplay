// Configuration for different environments
const config = {
  development: {
    API_URL: 'https://cmdb-backend-deployment-production.up.railway.app'
  },
  production: {
    API_URL: 'https://cmdb-backend-deployment-production.up.railway.app',
    BASE_URL: 'https://lightcoral-loris-143961.hostingersite.com/'
  }
};

const environment = import.meta.env.MODE || 'development';

export default config[environment]; 