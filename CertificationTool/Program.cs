using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CertificationTool
{
    class Program
    {
        static string CommonName { get; set; }
        static List<int> Ports { get; set; }
        static void Main(string[] args)
        {
            Ports = new List<int>();

            ReadCommonName(false);
            ReadPort(false);

            CertUtils.BindSslPort(CommonName, Ports);

            Console.WriteLine("Succeed!");
            Console.WriteLine();

            Console.WriteLine("Do you want to export this certificate to file? Press Y to export and other key to skip ...");
            if (Console.ReadLine().ToString().ToLower() == "y")
            {
                var filePath = CertUtils.ExportToFile();
                Console.WriteLine("Export to file succeed: ");
                Console.WriteLine(filePath);
                Console.WriteLine();
            }
            else
            {
                Console.WriteLine("Skipped.");
                Console.WriteLine();
            }

            Console.WriteLine("Application will exist in 5 seconds ...");
            System.Threading.Thread.Sleep(5 * 1000);
        }

        static void ReadCommonName(bool invalid)
        {
            if (invalid)
            {
                Console.WriteLine("Invalid common name!");
                Console.WriteLine("Please enter a valid common name: (length must greater than 0 and without any white space)");
            }
            else
            {
                Console.WriteLine("Please enter the common name:");
            }
            CommonName = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(CommonName) || CommonName.Contains(" "))
            {
                ReadCommonName(true);
            }
        }

        static void ReadPort(bool invalid)
        {
            if (invalid)
            {
                Console.WriteLine("Invalid port number!");
                Console.WriteLine("Please enter valid port numbers (0 ~ 65535):");
            }
            else
            {
                Console.WriteLine("Please enter the port number. Split with ',' if need bind to multiple ports: ");
                Console.WriteLine("e.g.: 50001,50002");
            }
            List<string> ports = Console.ReadLine().Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries).ToList();
            int tempPort;
            foreach (var port in ports)
            {
                if (!Int32.TryParse(port, out tempPort) || tempPort < 0 || tempPort > 65535)
                {
                    continue;
                }
                else
                {
                    Ports.Add(tempPort);
                }
            }

            if (Ports.Count == 0)
            {
                ReadPort(true);
            }
        }
    }
}
