var Connection = require('tedious').Connection;

var config = {
    server: '192.168.100.52/sql2017',
    authentication: {
        type: "default",
        options: {  
          userName: "sa",
          password: "Sigsa123",
        }
      },
    options: {
        port: 1433, // Default Port
        database: 'SBM_Puebla',
      },
}

var connection = new Connection(config);

connection.on('connect', function (err) {
    if (err) {
        console.log(err);
    } else {
        console.log('Connected');
    }
});

module.exports = connection;
