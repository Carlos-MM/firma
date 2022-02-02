const dbContext = require('../database/context');
const fs = require("fs");
const forge = require("node-forge");
const crypto = require("crypto");
const hash = require("object-hash");


function json(status,message,data){
    return {
        status: status,
        message : message,
        dato : data
     }
}

function pemToForgeCert(pem) {
    try {
      var pki = forge.pki;
      return pki.certificateFromPem(pem);
    } catch (e) {
      throw "Error al convertir la cadena PEM a un certificado forge";
    }
}

function pemToForgeKey(pemkey, pass ) {
    var pki = forge.pki;
    //privateKey es la llave privada
    var privateKey = null;
    try {
      privateKey = pki.decryptRsaPrivateKey(pemkey, pass);
    } catch (e) {
      throw "Error en la contraseña";
    }
    if (!privateKey) {
      throw "Error en la contraseña";
    }
    return privateKey;
}

function keyBufferToPem(derBuffer) 
{
    try {
      //recibe un buffer binario que se tiene que convertir a un buffer de node-forge
      var forgeBuffer = forge.util.createBuffer(derBuffer.toString("binary"));
      //hay que codificarlo como base64
      var encodedb64 = forge.util.encode64(forgeBuffer.data);
      //se le agregan '-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n' y '-----END ENCRYPTED PRIVATE KEY-----\r\n'
      //pkcs8PEM es la llave privada encriptada hay que desencriptarla con el password
      let pkcs8PEM =
        "" +
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n" +
        encodedb64 +
        "-----END ENCRYPTED PRIVATE KEY-----\r\n";
      return pkcs8PEM;
    } catch (e) {
      throw "Error al convertir la llave privada de archivo binario a formato pem";
    }
}

function certBufferToPem(derBuffer) {
    try {
      var forgeBuffer = forge.util.createBuffer(derBuffer.toString("binary"));
      //hay que codificarlo como base64
      var encodedb64 = forge.util.encode64(forgeBuffer.data);
      var certPEM =
        "" +
        "-----BEGIN CERTIFICATE-----\n" +
        encodedb64 +
        "\n-----END CERTIFICATE-----";
    } catch (e) {
      throw "Error a lconvertir el archivo a PEM";
    }
    return certPEM;
  }
function validaCertificadosFromPem(pempublica, pemprivada, passprivada ) {
    let cert = pemToForgeCert(pempublica);
    let privateKey = pemToForgeKey( pemprivada,passprivada);
    let forgePublicKey = forge.pki.setRsaPublicKey(privateKey.n,privateKey.e);
    return ( forge.pki.publicKeyToPem(forgePublicKey) === forge.pki.publicKeyToPem(cert.publicKey));
}

function validaRfcFromPem(pem, rfc) {
    let cer = pemToForgeCert(pem);
    try {
      for (var i = 0; i < cer.subject.attributes.length; i++) {
        var val = cer.subject.attributes[i].value;
        if(val!=='undefined')
        {
          var arrayDeCadenas = val.split('/');
          if (arrayDeCadenas[0].trim() == rfc.trim()) {
            return true;
          }
       }
      }
      return false;
    } catch (e) {
      throw "Error al validar el rfc apartir del certificado en formato PEM ";
    }
}
function certificadoExpirado(pempublica){
    let cert = pemToForgeCert(pempublica);
    var today = new Date().getTime();
    var from = cert.validity.notBefore.getTime();
    var to = cert.validity.notAfter.getTime();

    if (today < from || today > to) 
        return true;
    else
        return false;
}

function firmarCadena( pempublica, pemprivada, passprivada, cadena ) {
    try 
    {
        let cert = pemToForgeCert(pempublica);
        let privateKey = pemToForgeKey(pemprivada,passprivada);
        let p7 = forge.pkcs7.createSignedData();
        p7.content = forge.util.createBuffer(cadena, "utf8");
        p7.addCertificate(cert);
        p7.addSigner({key: privateKey, certificate: cert,digestAlgorithm: forge.pki.oids.sha256 });
        p7.sign({ detached: true }); 
        //console.log("-----------INICIANDO DESPLIEGUE DE LA FIRMA--------------------");
        //console.log(p7);
        //console.log("-----------INICIANDO ENCRIPTADO DE LA FIRMA--------------------");
        let pem = forge.pkcs7.messageToPem(p7);

        //let p7d = forge.pkcs7.messageFromPem(pem)
        //let privateCert = forge.pki.decryptRsaPrivateKey(fs.readFileSync("prueba.cer"),passprivada);
        //p7d.decrypt(p7d.recipients[0], privateCert);
        //console.log(p7d.content)

        return pem;
    }
    catch (e) 
    {
        return null;
    }
}
function verificarFirma(pempublica, cadena, pemfirma ) {
  try {
    // pemfirma is the extracted Signature from the S/MIME
    // with added -----BEGIN PKCS7----- around it
    let msg = forge.pkcs7.messageFromPem(pemfirma);
    //var attrs = msg.rawCapture.authenticatedAttributes; // got the list of auth attrs
    let sig = msg.rawCapture.signature;
    //var set = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, attrs); // packed them inside of the SET object
    let buf = Buffer.from(cadena, "binary");
    //var buf = Buffer.from(cadena, "binary");

    //esta lógica solo verifica que los dos certificados sean iguales el del mensaje firmado y el proporcionado por el usuario
    //si se utilizan cadenas de certificados entonces habria que deshabilitar esta parte
    let certfirmado = msg.certificates[0];
    let certpublico = forge.pki.certificateFromPem(pempublica);
    let algo1 = hash(certfirmado);
    let algo2 = hash(certpublico);
    if (algo1 !== algo2) {
      throw "El certificado del firmado no es el mismo que el certificado proporcionado";
    }
    //esta lógica solo verifica que los dos certificados sean iguales el del mensaje firmado y el proporcionado por el usuario

    //la verificacion de firmas pkcs#7 no ha sido implementada en node-forge
    //por eso se usa la libreria crypto la cual la resuelve como pkcs#1
    let verifier = crypto.createVerify("RSA-SHA256");
    verifier.update(buf);
    var verified = verifier.verify(
      forge.pki.certificateToPem(certpublico),
      sig,
      "binary"
    );

    return verified;
  } catch (e) {
    return { status: "error al verificar cadena"+e };
  }
}  
/*
exports.verificaFirmaDigital=(req,res)=>
{
  var publicKey = fs.readFileSync("C:\\inetpub\\wwwroot\\apitramites\\Upload\\certificados\\"+filecer);
  const pemPublicKey = certBufferToPem(publicKey);
  var valid = verificarFirma(pemPublicKey,nrotramite,firma);

}*/
exports.getSignature=(req,res)=>
{
 /* let rfc = "LAN7008173R5";         //rfc
  let password = "12345678a";       //contraseña de la llave privada
  let cadena = "ESTA ES UNA FIRMA DIGITAL DE PRUEBA PARA EL LUNES"; //cadena a firmar
*/
    let result=null;
    //console.log("body: ",req.body);
    let rfc =req.body.rfc;        //rfc
    let password =req.body.password;       //contraseña de la llave privada
    let cadena =req.body.nrotramite; //cadena a firmar
    let filekey=req.body.namekey; //
    let filecer=req.body.namecert;
    let carpeta=req.body.usuario;
    let firma = null;                 //objeto donde quedara la firma

    /*fs.writeFile('C:\\D\\parametros.txt', cadena, function (err) {
      if (err) throw err;
      console.log('Saved!');
    });*/
   

    //leemos los certificados productivo
    let privateKey = fs.readFileSync("C:\\SB_DocumentosPuebla\\Certificados\\"+carpeta+"\\"+filekey);
    let publicKey = fs.readFileSync("C:\\SB_DocumentosPuebla\\Certificados\\"+carpeta+"\\"+filecer);
    //leemos los certificados desarrollo
    //let privateKey = fs.readFileSync("C:\\D\\Proyectos\\FirmaElectronica\\ApiRestTramites\\ApiRestTramites\\Upload\\certificados\\"+filekey);
    //let publicKey  = fs.readFileSync("C:\\D\\Proyectos\\FirmaElectronica\\ApiRestTramites\\ApiRestTramites\\Upload\\certificados\\"+filecer);

    //convertir el archivo a formato PEM
    let pemPrivateKey = keyBufferToPem(privateKey);
    let pemPublicKey = certBufferToPem(publicKey);
    //console.log(pemPrivateKey);
    //console.log(pemPublicKey);

    if(validaRfcFromPem(pemPublicKey, rfc))
    {
        if (validaCertificadosFromPem(pemPublicKey,pemPrivateKey,password)  ) 
        {
            //if(!certificadoExpirado(pemPublicKey))
            //{
                firma=firmarCadena(pemPublicKey,pemPrivateKey,password,cadena);

                if(firma!==null)
                {
                    result=json(true,"Firma electrónica exitosa",firma);
                    //var valid = verificarFirma(pemPublicKey,nrotramite,firma);
                    //console.log("Validacion de la firma electronica:"+JSON.stringify(valid));
                }
                else
                    result=json(false,"Error al generar la firma",firma);
            //}
            //else
            //    result=json(false,"El certificado ha expirado",firma);
        }
        else
            result=json(false,"El certificado no corresponde con la llave" ,firma);
    }
    else
        result=json(false,"El RFC no corresponde con el certificado" ,firma);
    
   return res.json(result);
}


exports.getSignatureLoggedIn=(req,res)=>
{
    return res.json(json(true, "Firma electronica con login", 'Usuario logeado'));
}

exports.getInfoSignature=(req,res)=>
{
  //console.log("body 2:", req.body);
  //let filename =req.params.filename; 
  let filename =req.body.namecert;
  let carpeta=req.body.usuario;
  let result=null;
  //leemos el certificado en productivo
    var publicKey = fs.readFileSync("C:\\SB_DocumentosPuebla\\Ccertificados\\"+carpeta+"\\"+filename);
  //leemos el certificado en desarrollo
  //var publicKey = fs.readFileSync("C:\\D\\Proyectos\\FirmaElectronica\\ApiRestTramites\\ApiRestTramites\\Upload\\certificados\\"+filename);

  const pemPublicKey = certBufferToPem(publicKey);

  /*var forgeBuffer = forge.util.createBuffer(publicKey);
  var encodedb64 = forge.util.encode64(forgeBuffer.data);
  var certPEM =
  "" +
  "-----BEGIN CERTIFICATE-----\n" +
  encodedb64 +
  "\n-----END CERTIFICATE-----";
  */
  try{
	  var pki = forge.pki;
	  //var crt = pki.certificateFromPem(certPEM);
	  var crt = pki.certificateFromPem(pemPublicKey);
	  //console.log(crt.subject.attributes);
	  let email='NA';
	  let organizacion='NA';
	  
	  try { if(crt.subject.getField('E').value !== null) email=crt.subject.getField('E').value } catch(e) {  }
	  try { if(crt.subject.getField('OU').value !== null) organizacion=crt.subject.getField('OU').value } catch(e) {  }
	   
	  let data = {
		subjectCn: crt.subject.getField('CN').value===null?'No aplica':crt.subject.getField('CN').value,
		organizationName: crt.subject.getField('O').value===null?'No aplica':crt.subject.getField('O').value,
		emailAddress:email,
		organizationalUnitName:organizacion,
		issuerCn: crt.issuer.getField('CN').value===null?'No aplica':crt.issuer.getField('CN').value,
		countryName: crt.issuer.getField('C').value===null?'No aplica':crt.issuer.getField('C').value,
		organizationNameSAT: crt.issuer.getField('O').value===null?'No aplica':crt.issuer.getField('O').value,
		organizationalUnitNameSAT:crt.issuer.getField('OU').value===null?'No aplica':crt.issuer.getField('OU').value,
		emailAddressSAT:crt.issuer.getField('E').value===null?'No aplica':crt.issuer.getField('E').value,
		serialNumber: crt.serialNumber,
		notBefore: crt.validity.notBefore,
		notAfter: crt.validity.notAfter,
		rfc:crt.subject.getField({type: '2.5.4.45'}).value.split(' ')[0] || ''
	  };
	  
		result=json(true,"",data);
	     
  }
  catch (e)
  {
	  result=json(false,"No se pudo leer la información del certificado"+e,null);
  }
  
  return res.json(result);

}