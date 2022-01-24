var Connection=require('tedious').Connection;
var request=require('tedious').Request;

var config = {
  server: "192.168.100.52/sql2017", // or "localhost"
  options: {
    port: 1433, // Default Port
    database: 'SBM_Puebla',
  },
  authentication: {
    type: "default",
    options: {  
      userName: "sa",
      password: "Sigsa123",
    }
  }
};

var connection = new Connection(config);

connection.on('connect', function (err) {
    if (err) {
        console.log(err);
    } else {
        console.log('Connected');
    }
});

module.exports=
{
  connection:connection,
  JWT_KEY:"secret"

};