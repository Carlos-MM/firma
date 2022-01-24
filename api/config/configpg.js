const Promise = require('bluebird');
const initOptions = {
    promiseLib: Promise
};
const pgp = require('pg-promise')(initOptions);
var connectionString = 'postgres://postgres:jalmsck@localhost:5432/bienespatrimoniales';
let db = pgp(connectionString);

module.exports=
{
  db:db,
  JWT_KEY:"secret"

};