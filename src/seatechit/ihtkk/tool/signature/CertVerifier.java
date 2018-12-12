package seatechit.ihtkk.tool.signature;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Vector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.UnknownStatus;

public class CertVerifier
{
  protected static final String X509_CERTIFICATE_TYPE = "X.509";
  protected static final String CERT_CHAIN_ENCODING = "PkiPath";
  protected static final String DIGITAL_SIGNATURE_ALGORITHM_NAME = "SHA1withRSA";
  protected static final String CERT_CHAIN_VALIDATION_ALGORITHM = "PKIX";
  public static final int CERT_STATUS_ERROR = -1;
  public static final int CERT_STATUS_GOOD = 0;
  public static final int CERT_STATUS_REVOKED = 1;
  public static final int CERT_STATUS_UNKNOWN = 2;
  protected X509Certificate[] rootCerts;
  protected X509Certificate[] trustedCerts;
  
  public CertVerifier(X509Certificate[] rootCerts, X509Certificate[] trustedCerts)
  {
    this.rootCerts = rootCerts;
    this.trustedCerts = trustedCerts;
  }
  
  public void verifyCertificationChain(Date dValidity, X509Certificate cert, X509Certificate[] certChain)
    throws Exception
  {
    Security.addProvider(new BouncyCastleProvider());
    if (dValidity != null) {
      try
      {
        cert.checkValidity(dValidity);
      }
      catch (CertificateExpiredException ex)
      {
        throw new ITaxCertValidException("Ch?ng th? s? ?� h?t hi?u l?c.");
      }
      catch (CertificateNotYetValidException ex)
      {
        throw new ITaxCertValidException("Ch?ng th? s? ch?a c� hi?u l?c.");
      }
    }
    if (certChain.length < 2)
    {
      verifyCertificate(cert);
      return;
    }
    try
    {
      CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
      CertPath certPath = certFactory.generateCertPath(Arrays.asList(certChain));
      
      HashSet trustAnchors = new HashSet();
      for (int i = 0; i < this.rootCerts.length; i++)
      {
        TrustAnchor trustAnchor = new TrustAnchor(this.rootCerts[i], null);
        trustAnchors.add(trustAnchor);
      }
      PKIXParameters certPathValidatorParams = new PKIXParameters(trustAnchors);
      certPathValidatorParams.setRevocationEnabled(false);
      CertPathValidator chainValidator = CertPathValidator.getInstance(CertPathValidator.getDefaultType(), new BouncyCastleProvider());
      
      CertPath certChainForValidation = removeLastCertFromCertChain(certPath);
      try
      {
        chainValidator.validate(certChainForValidation, certPathValidatorParams);
      }
      catch (Exception ex)
      {
        try
        {
          verifyCertificate(cert);
        }
        catch (Exception exx)
        {
          throw new ITaxCertValidException("Ch?ng th? s? kh�ng h?p ph�p (" + ex.getMessage() + ").");
        }
        ex.printStackTrace();
      }
      
      return;
    }
    catch (GeneralSecurityException ex)
    {
      throw new ITaxCertValidException("Ch?ng th? s? kh�ng h?p ph�p (" + ex.getMessage() + ").");
    }
  }
  
  public void verifyCertificate(X509Certificate aCertificate)
    throws Exception
  {
    X509Certificate issuerCert = null;
    for (int i = 0; i < this.trustedCerts.length; i++)
    {
      issuerCert = this.trustedCerts[i];
      
      issuerCert = null;
    }
    if (issuerCert != null) {
      try
      {
        aCertificate.verify(issuerCert.getPublicKey());
        return;
      }
      catch (GeneralSecurityException ex)
      {
        throw new ITaxCertValidException("Ch?ng th? s? kh�ng h?p ph�p (" + ex.getMessage() + ").");
      }
    }
    throw new ITaxCertValidException("Kh�ng t�m th?y ch?ng th? s? c?a nh� cung c?p d?ch v? ch?ng th? s? (" + aCertificate.getIssuerDN().getName() + ").");
  }
  
  private OCSPReq generateOCSPRequest(X509Certificate issuerCert, BigInteger serialNumber)
    throws OCSPException
  {
    Security.addProvider(new BouncyCastleProvider());
    
    CertificateID id = new CertificateID("1.3.14.3.2.26", 
      issuerCert, serialNumber);
    
    OCSPReqGenerator gen = new OCSPReqGenerator();
    
    gen.addRequest(id);
    
    BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
    Vector oids = new Vector();
    Vector values = new Vector();
    
    oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
    values.add(new X509Extension(false, new DEROctetString(nonce.toByteArray())));
    
    gen.setRequestExtensions(new X509Extensions(oids, values));
    
    return gen.generate();
  }
  
  public void checkRevocationStatus(X509Certificate cert, X509Certificate[] issuerCerts)
    throws Exception
  {
    X509Certificate issuerCert = null;
    for (int i = 0; i < issuerCerts.length; i++)
    {
      issuerCert = issuerCerts[i];
     
      issuerCert = null;
    }
    if (issuerCert == null) {
      throw new ITaxStatusValidException("Kh�ng t�m th?y ch?ng th? s? c?a nh� cng c?p d?ch v? ch?ng th? s? (" + cert.getIssuerDN().getName() + ").");
    }
    checkRevocationStatus(cert, issuerCert);
  }
  
  public void checkRevocationStatus(X509Certificate cert, X509Certificate issuerCert)
    throws Exception
  {
    List<String> locations = getOcspUrl(cert);
    for (String serviceUrl : locations) {
      try
      {
        if (serviceUrl.startsWith("http"))
        {
          OCSPReq request = generateOCSPRequest(issuerCert, cert.getSerialNumber());
          
          byte[] array = request.getEncoded();
          HttpURLConnection con = null;
          URL url = new URL(serviceUrl);
          con = (HttpURLConnection)url.openConnection();
          con.setRequestProperty("Content-Type", "application/ocsp-request");
          con.setRequestProperty("Accept", "application/ocsp-response");
          con.setDoOutput(true);
          OutputStream out = con.getOutputStream();
          DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));
          
          dataOut.write(array);
          
          dataOut.flush();
          dataOut.close();
          if (con.getResponseCode() / 100 != 2) {
            throw new ITaxStatusValidException("Kh�ng th? k?t n?i Internet t?i ??n v? CA ?? ki?m tra t�nh tr?ng thu h?i c?a ch?ng th? s?");
          }
          InputStream in = (InputStream)con.getContent();
          OCSPResp ocspResponse = new OCSPResp(in);
          BasicOCSPResp basicResponse = (BasicOCSPResp)ocspResponse.getResponseObject();
          if (basicResponse != null)
          {
            SingleResp[] responses = basicResponse.getResponses();
            if (responses.length == 1)
            {
              SingleResp resp = responses[0];
              Object status = resp.getCertStatus();
              if ((status instanceof RevokedStatus)) {
                throw new ITaxStatusValidException("Ch?ng th? s? ?� b? thu h?i.");
              }
              if ((status instanceof UnknownStatus)) {
                throw new ITaxStatusValidException("Kh�ng th? ki?m tra t�nh tr?ng thu h?i c?a ch?ng th? s?.");
              }
            }
          }
        }
      }
      catch (Exception e)
      {
        throw new ITaxStatusValidException("Kh�ng th? ki?m tra t�nh tr?ng thu h?i c?a ch?ng th? s? (" + e.getLocalizedMessage() + ")");
      }
    }
  }
  
  private List<String> getOcspUrl(X509Certificate cert)
    throws Exception
  {
    List<String> ocspUrlList = getX509Extensions(cert, "1.3.6.1.5.5.7.48.1");
    if (ocspUrlList.isEmpty()) {
      throw new ITaxStatusValidException("Kh�ng th? ??c th�ng tin v? URI d�ng ?? ki?m tra tr?ng th�i thu h?i c?a ch?ng th? s?");
    }
    return ocspUrlList;
  }
  
  private List<String> getX509Extensions(X509Certificate cert, String OID)
    throws Exception
  {
    List<String> extValues = new ArrayList();
    try
    {
      byte[] bytes = cert.getExtensionValue(X509Extensions.AuthorityInfoAccess.getId());
      ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(bytes));
      ASN1OctetString octs = (ASN1OctetString)ais.readObject();
      ais = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
      
      ASN1Sequence accessDescriptions = (ASN1Sequence)ais.readObject();
      for (int i = 0; i < accessDescriptions.size(); i++)
      {
        ASN1Sequence accessDescription = (ASN1Sequence)accessDescriptions.getObjectAt(i);
        if (((DERObjectIdentifier)accessDescription.getObjectAt(0)).getId().equals(OID))
        {
          DERTaggedObject taggedObject = (DERTaggedObject)accessDescription.getObjectAt(1);
          extValues.add(new String(ASN1OctetString.getInstance(taggedObject, false).getOctets(), "ISO-8859-1"));
        }
      }
    }
    catch (Exception e)
    {
      throw new ITaxStatusValidException("Kh�ng c� th�ng tin v? CA trong ch?ng th? s?");
    }
    return extValues;
  }
  
  private CertPath removeLastCertFromCertChain(CertPath aCertChain)
    throws CertificateException
  {
    List certs = aCertChain.getCertificates();
    int certsCount = certs.size();
    List certsWithoutLast = certs.subList(0, certsCount - 1);
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    CertPath certChainWithoutLastCert = cf.generateCertPath(certsWithoutLast);
    return certChainWithoutLastCert;
  }
  
  public static X509Certificate loadX509CertificateFromStream(InputStream aCertStream)
    throws CertificateException
  {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate cert = (X509Certificate)cf.generateCertificate(aCertStream);
    return cert;
  }
  
 
}
