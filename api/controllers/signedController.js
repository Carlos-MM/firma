const firmafiel = require("@gobmx-sfp/firmafiel");
const fs = require("fs");
const forge = require("node-forge");
const Credential=require("@nodecfdi/credentials");

function getStandardResponse(status,message,data){
    return {
        status: status,
        message : message,
        data : data
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

function validaCertificadosFromPem(pempublica, pemprivada, passprivada ) {
  const cert = pemToForgeCert(pempublica);
  const privateKey = pemToForgeKey( pemprivada,passprivada);
  const forgePublicKey = forge.pki.setRsaPublicKey(privateKey.n,privateKey.e);
  console.log("----------------------------------inicia comparacion de certificados-----------------------------")
  console.log(forge.pki.publicKeyToPem(forgePublicKey));
  console.log(forge.pki.publicKeyToPem(cert.publicKey));
  console.log("----------------------------------finaliza comparacion de certificados-----------------------------")
  return ( forge.pki.publicKeyToPem(forgePublicKey) === forge.pki.publicKeyToPem(cert.publicKey));
}
function firmarCadena( pempublica, pemprivada, passprivada, cadena ) {
  try {
    if (validaCertificadosFromPem(pempublica,pemprivada,passprivada)  ) 
    {
      console.log("Certificados validos");
      const cert = pemToForgeCert(pempublica);

      var today = new Date().getTime();
      var from = cert.validity.notBefore.getTime();
      var to = cert.validity.notAfter.getTime();

      /*if (today < from || today > to) {
        console.log("Certificado ha expirado");
        throw "El certificado ha expirado";
      }*/

      const privateKey = pemToForgeKey(pemprivada,passprivada);
      const p7 = forge.pkcs7.createSignedData();
      p7.content = forge.util.createBuffer(cadena, "utf8");
      console.log("Comienza firma");
      p7.addCertificate(cert);
      p7.addSigner({key: privateKey, certificate: cert,digestAlgorithm: forge.pki.oids.sha256 });
      p7.sign({ detached: true }); //es importante poner {detached:true} porque si no , se anexan los datos sin encriptar es decir cualquiera con la firma puede ver los datos firmados
      const pem = forge.pkcs7.messageToPem(p7);
      return { status: "ok", firmapem: pem };
    }
  } catch (e) {
    return { status: "error en el firmado:" + e.stack };
  }
}

function validaRfcFromPem(pem, rfc) {
  const cer = pemToForgeCert(pem);
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
function checkCertificate() {
  try {
   var crt = pki.certificateFromPem(fs.readFileSync("prueba.cer"));
   console.log("RESULTADO DE LA EJECUCION DE CETIFICADOFROMPEM");
   console.log(crt.publicKey.n.toString(2).length);
   if (crt.publicKey.n.toString(2).length < 2048) {
    return false;
   }
   return /^whistle\.\d+$/.test(getCommonName(crt));
  } catch(e) {}
  return true;
 }

async function test () {
  console.log('**********************************VERIFICA CERTIFICADO*****************************************************************');
    //checkCertificate();
    var forgeBuffer = forge.util.createBuffer(fs.readFileSync("prueba.cer"));
    //hay que codificarlo como base64
    var encodedb64 = forge.util.encode64(forgeBuffer.data);
    var certPEM =
      "" +
      "-----BEGIN CERTIFICATE-----\n" +
      encodedb64 +
      "\n-----END CERTIFICATE-----";

    var pki = forge.pki;
    var crt = pki.certificateFromPem(certPEM);
    console.log(crt);
    console.log(JSON.stringify(crt));
    console.log("Inicia recorrido de valores\n");
    //console.log( crt)
    const data = {
      subjectCn: crt.subject.getField('CN').value,
      issuerCn: crt.issuer.getField('CN').value,
      countryName: crt.issuer.getField('C').value,
      organizationName: crt.issuer.getField('O').value,
      serialNumber: crt.serialNumber,
      notBefore: crt.validity.notBefore,
      notAfter: crt.validity.notAfter,
      rfc:crt.subject.getField({type: '2.5.4.45'}).value
    };
    console.log("Impresion de valores\n");
    console.log(data);
    for (var i = 0; i < crt.subject.attributes.length; i++) 
    {
      try
      {
      var val = crt.subject.attributes[i].value.trim();
      console.log(val);
      if (val == rfc.trim()) {
        console.log("RFC si es IGUAL");
      }
    }
    catch(e)
    {


    }
      

    }


    console.log('**********************************FIN VERIFICA CERTIFICADO*****************************************************************');
   
   




















    var privateKey = fs.readFileSync("prueba.key");
    var publicKey = fs.readFileSync("prueba.cer");

    //convertir el archivo a formato PEM
    const pemPublicKey = firmafiel.certBufferToPem({ derBuffer: publicKey });
    
    //verifica el certificado via ocsp 
    //var prueba = await firmafiel.verificarCertificado({
    //  certificado: pemPublicKey
    //});
   
    var rfc = "LAN7008173R5"; //rfc
    var password = "12345678a"; //contraseña de la llave privada
    var cadena = "TEST"; // cadena a firmar
    var firma = null; //objeto donde quedara la firma
  
    const pemPrivateKey = firmafiel.keyBufferToPem({ derBuffer: privateKey });
    console.log('**********************************VALIDA RFC*****************************************************************');
    //console.log(pemPublicKey)
    var value=validaRfcFromPem(pemPublicKey, rfc);
    console.log(value);
    console.log('***********************************VALIDA RFC****************************************************************');

    var firma=firmarCadena(pemPublicKey,pemPrivateKey,password,cadena);

    console.log(firma);
    //console.log(pemPublicKey);
    //console.log(firmafiel.validaRfcFromPem({ pem: pemPublicKey, rfc: rfc }));
   //si el resultado de la verificación OCSP es goood y  el rfc que tenemos(provisto por la aplicación que use esta libreria) coincide con el del certificado
   //entonces procedemos a firmar la cadena 
   //const pem = firmafiel.certBufferToPem({ derBuffer: publickey });
   //const forgeCert = firmafiel.pemToForgeCert({ pem: pemPublicKey });
   //const validado = firmafiel.validaRfcFromForgeCert({
   //             cer: forgeCert,
   //             rfc: "LAN7008173R5"
   //             });
   //console.log(validado);
   /*
   if (
      //prueba.data.status === "good" && //good revoked unknown
      firmafiel.validaRfcFromPem({ pem: pemPublicKey, rfc: rfc }) //verificacion de rfc de la aplicación con el del certificado
    ) {
        console.log('RF Correcto.............................')
      //firmamos la cadena y obtenemos el objeto firma
      firma = firmafiel.firmarCadena({  //firma : { status: "ok", firmapem: "-----BEGIN PKCS7-----" }
        pempublica: pemPublicKey,
        pemprivada: pemPrivateKey,
        passprivada: password,
        cadena: cadena
      });
  
      console.log(firma); // { status: "ok", firmapem: "-----BEGIN PKCS7-----" };
    }
    else
        console.log('RFC InCorrecto.............................')
    //verificarFirma regresa true | false
    var valid = firmafiel.verificarFirma({
      pempublica: pemPublicKey,
      cadena: "TEST",
      pemfirma: firma.firmapem
    });
  
    console.log(valid); //true | false
*/


  };
  

function credentials()
{
// se puede mandar el path o el contenido
const certFile = fs.readFileSync('prueba.cer');
const keyFile = fs.readFileSync('prueba.key');
const passPhrase = '12345678a'; // contraseña para abrir la llave privada
console.log("Crea credenciales");
const fiel = Credential.create( certFile, keyFile, passPhrase);

const sourceString = 'TEST';
// alias de privateKey/sign/verify
const signature = fiel.sign(sourceString);
console.log(signature);

// alias de certificado/publicKey/verify
const verify = fiel.verify(sourceString, signature);
console.log(verify); // boolean(true)

// objeto certificado
const certificado = fiel.certificate();
console.log(certificado.rfc()); // el RFC del certificado
console.log(certificado.legalName()); // el nombre del propietario del certificado
console.log(certificado.branchName()); // el nombre de la sucursal (en CSD, en FIEL está vacía)
console.log(certificado.serialNumber().bytes()); // número de serie del certificado

}

exports.getFirma=(req,res,next)=>{
    //test();
    credentials();
    return res.json(getStandardResponse(true, "", 'topics'));
}
