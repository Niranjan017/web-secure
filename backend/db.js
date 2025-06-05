const { Pool } = require('pg');

const pool = new Pool({
  user: 'postgres',        
  host: 'localhost',
  database: 'websecura',    
  password: '8641',
  port: 5432,
});

module.exports = pool;
