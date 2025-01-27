package se.oidc.oidfed.md.wallet.data;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Test data for unit testing
 */
public class TestData {

  public static final X509Certificate testEntityCert;


  static {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    try {
      testEntityCert = convertPemToX509Certificate(TestData.class.getResource("/test-entity.crt").getPath());
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }

  }

  public static X509Certificate convertPemToX509Certificate(String path) throws Exception {
    try (InputStream resStream = new BufferedInputStream(new FileInputStream(path))) {
      CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");
      return (X509Certificate) certificateFactory.generateCertificate(resStream);
    }
  }

}
