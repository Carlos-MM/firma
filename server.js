const http=require('http');
const app=require ('./app');
const port=process.env.PORT || 8090;
const server=http.createServer(app);
app.listen(port, () => {
    console.log("Ejecutandose en el puerto "+port);
});
//server.listen(port);