using CERTENROLLLib;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
namespace CertificationTool
{
    public class CertUtils
    {
        public static string SUBJECTNAME { get; set; }
        static X509Certificate2 certificate; 
        static X509Certificate2 CreateSelfSignedCertificate()
        {
            Console.WriteLine("Create self-signed certificate with common name: " + SUBJECTNAME);

            // create DN for subject and issuer
            var dn = new CX500DistinguishedName();
            dn.Encode("CN=" + SUBJECTNAME, X500NameFlags.XCN_CERT_NAME_STR_NONE);

            // create a new private key for the certificate
            CX509PrivateKey privateKey = new CX509PrivateKey();
            privateKey.ProviderName = "Microsoft Base Cryptographic Provider v1.0";
            privateKey.MachineContext = true;
            privateKey.Length = 2048;
            privateKey.KeySpec = X509KeySpec.XCN_AT_SIGNATURE; // use is not limited
            privateKey.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
            privateKey.Create();

            // Use the stronger SHA512 hashing algorithm
            var hashobj = new CObjectId();
            hashobj.InitializeFromAlgorithmName(ObjectIdGroupId.XCN_CRYPT_HASH_ALG_OID_GROUP_ID,
                ObjectIdPublicKeyFlags.XCN_CRYPT_OID_INFO_PUBKEY_ANY,
                AlgorithmFlags.AlgorithmFlagsNone, "SHA512");

            // add extended key usage if you want - look at MSDN for a list of possible OIDs
            var oid1 = new CObjectId();
            oid1.InitializeFromValue("1.3.6.1.5.5.7.3.1"); // 服务器身份验证

            var oid2 = new CObjectId();
            oid2.InitializeFromValue("1.3.6.1.5.5.7.3.2"); // 客户端身份验证

            var oidlist = new CObjectIds();
            oidlist.Add(oid1);
            oidlist.Add(oid2);
            var eku = new CX509ExtensionEnhancedKeyUsage();
            eku.InitializeEncode(oidlist);

            // Create the self signing request
            var cert = new CX509CertificateRequestCertificate();
            cert.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextMachine, privateKey, "");
            cert.Subject = dn;
            cert.Issuer = dn; // the issuer and the subject are the same
            cert.NotBefore = DateTime.Now.AddDays(-10);
            // this cert expires immediately. Change to whatever makes sense for you
            cert.NotAfter = DateTime.Now.AddYears(10);
            cert.X509Extensions.Add((CX509Extension)eku); // add the EKU
            cert.HashAlgorithm = hashobj; // Specify the hashing algorithm
            cert.Encode(); // encode the certificate

            // Do the final enrollment process
            var enroll = new CX509Enrollment();
            enroll.InitializeFromRequest(cert); // load the certificate
            enroll.CertificateFriendlyName = SUBJECTNAME; // Optional: add a friendly name
            string csr = enroll.CreateRequest(); // Output the request in base64
            // and install it back as the response
            enroll.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedCertificate,
                csr, EncodingType.XCN_CRYPT_STRING_BASE64, ""); // no password
            // output a base64 encoded PKCS#12 so we can import it back to the .Net security classes
            var base64encoded = enroll.CreatePFX("", // no password, this is for internal consumption
                PFXExportOptions.PFXExportChainWithRoot);

            // instantiate the target class with the PKCS#12 data (and the empty password)
            return new System.Security.Cryptography.X509Certificates.X509Certificate2(
                System.Convert.FromBase64String(base64encoded), "",
                // mark the private key as exportable (this is usually what you want to do)
                System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable
            );
        }

        static void RemoveExistsCerts()
        {
            Console.WriteLine("Remove exists certificates ..." + SUBJECTNAME);
            for (var i = 1; i < 9; i++)
            {
                try
                {
                    var storeName = (StoreName)i;
                    var store = new X509Store(storeName, StoreLocation.LocalMachine);
                    store.Open(OpenFlags.ReadWrite | OpenFlags.IncludeArchived);
                    X509Certificate2Collection cers = store.Certificates.Find(X509FindType.FindBySubjectName, SUBJECTNAME, false);
                    foreach (var cer in cers)
                    {
                        store.Remove(cer);
                    }
                    store.Close();
                }
                catch (Exception e)
                {
                    Console.WriteLine("RemoveExistsCerts fail :" + e.Message);
                }
            }
        }

        static string ExportToFile(X509Certificate cert)
        {
            StringBuilder builder = new StringBuilder();

            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");

            return builder.ToString();
        }

        public static string ExportToFile()
        {
            var filePath = @"C:\Certificate.cer";
            File.WriteAllText(filePath, ExportToFile(certificate));
            return filePath;
        }

        static void AddCertToAuthRoot()
        {
            Console.WriteLine("Add certificate to trusted root ...");
            X509Store trustedPublisherStore = new X509Store(StoreName.TrustedPublisher, StoreLocation.LocalMachine);
            X509Store trustedAuthRootStore = new X509Store(StoreName.AuthRoot, StoreLocation.LocalMachine);
            X509Store trustedRootStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            X509Store trustedPeopleStore = new X509Store(StoreName.TrustedPeople, StoreLocation.LocalMachine);
            try
            {
                trustedPublisherStore.Open(OpenFlags.ReadWrite);
                trustedPublisherStore.Add(certificate);

                trustedAuthRootStore.Open(OpenFlags.ReadWrite);
                trustedAuthRootStore.Add(certificate);

                trustedRootStore.Open(OpenFlags.ReadWrite);
                trustedRootStore.Add(certificate);

                trustedPeopleStore.Open(OpenFlags.ReadWrite);
                trustedPeopleStore.Add(certificate);
            }
            catch (Exception ex)
            {
                Console.WriteLine("AddCertToAuthRoot fail :" + ex.Message);
            }
            finally
            {
                trustedPublisherStore.Close();
                trustedAuthRootStore.Close();
                trustedRootStore.Close();
                trustedPeopleStore.Close();
            }
        }

        public static void BindSslPort(List<int> ports)
        {
            if (string.IsNullOrEmpty(SUBJECTNAME))
            {
                Console.WriteLine("Invalid common name!");
                return;
            }

            RemoveExistsCerts();
            certificate = CertUtils.CreateSelfSignedCertificate();
            AddCertToAuthRoot();

            foreach (var port in ports)
            {
                BindSslPort(port);
            }
        }

        static void BindSslPort(int port)
        {
            Console.WriteLine("Begin to bind port: " + port);
            var bindPortToCertificate = new Process();
            bindPortToCertificate.StartInfo.FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.SystemX86), "netsh.exe");
            bindPortToCertificate.StartInfo.Arguments = string.Format("http delete sslcert ipport=0.0.0.0:{0}", port);
            bindPortToCertificate.Start();
            bindPortToCertificate.WaitForExit(200);

            bindPortToCertificate = new Process();
            bindPortToCertificate.StartInfo.FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.SystemX86), "netsh.exe");
            bindPortToCertificate.StartInfo.Arguments = string.Format("http add sslcert ipport=0.0.0.0:{0} certhash={1} appid={{{2}}}", port, certificate.Thumbprint, new Guid("73D4C11F-EA4F-4A33-8235-1DB0B0C943D2"));
            bindPortToCertificate.Start();
            bindPortToCertificate.WaitForExit(200);
            Console.WriteLine("Bind port to SSL succeed! ");
        }
    }
}
