// Follow the steps in the webpate(https://dax.tips/2020/07/09/using-visual-studio-code-with-power-bi/) file to run the code
// Step 1 : Install .Net Core SDK
// Step 2 : Create a C# console app
//          dotnet new console
// Step 4 : Add TOM client libraries
//          dotnet add package Microsoft.AnalysisServices.NetCore.retail.amd64 --version 19.4.0.2-Preview
// Step 5 : Add the code below for Program.cs file
// Step 6 : Open PowerBI desktop, find its port number, please refer the forth method in following webpage：
// https://www.biinsight.com/four-different-ways-to-find-your-power-bi-desktop-local-port-number/
// C:\Users\zhaohuisun>TASKLIST /FI "imagename eq msmdsrv.exe" /FI "sessionname eq console"

// Image Name                     PID Session Name        Session#    Mem Usage
// ========================= ======== ================ =========== ============
// msmdsrv.exe                   9832 Console                    1    507,692 K

// C:\Users\zhaohuisun>netstat /ano | findstr "9832"
//   TCP    127.0.0.1:52345        0.0.0.0:0              LISTENING       9832
//   TCP    [::1]:52345            [::]:0                 LISTENING       9832
//   TCP    [::1]:52345            [::1]:52347            ESTABLISHED     9832
//   TCP    [::1]:52345            [::1]:52350            ESTABLISHED     9832
//   TCP    [::1]:52345            [::1]:52351            ESTABLISHED     9832
//   TCP    [::1]:52345            [::1]:52402            ESTABLISHED     9832
//   TCP    [::1]:52345            [::1]:52419            ESTABLISHED     9832
//   TCP    [::1]:52345            [::1]:52420            ESTABLISHED     9832
// Step 7 : Change the port number and run the code
//          dotnet run
// Step 8 : Refresh dataset in powerBI desktop app, check if measures and table is refreshed.
//          Publish it to SONiC workspace.
using System;
using Microsoft.AnalysisServices.Tabular;
using System.IO;
 
namespace PBI_Tool
{
    class Program
    {
        static void Main(string[] args)
        {
            Server server = new Server();
            int portNumber = 52345;
            server.Connect($"localhost:{portNumber}");
 
            Model model =  server.Databases[0].Model;
 

            string outputFolderPath = "output";
            string[] txtFiles = Directory.GetFiles(outputFolderPath, "*.txt");

            // Remove all measures from the model for table SONiCKusto and PipelineRuns
            foreach (Table table in model.Tables)
            {
                Console.WriteLine($"Table : {table.Name}");
                if (table.Name == "SONiCKusto" || table.Name == "PipelineRuns")
                {
                    foreach (Measure measure in table.Measures)
                    {
                        Console.WriteLine($"measure : {measure.Name}");
                        table.Measures.Remove(measure);
                    }
                }
            }
            model.SaveChanges();
            foreach (string txtFile in txtFiles)
            {
                Table table2 = null;
                Console.WriteLine($"txtFile : {txtFile}");
                if (txtFile.Contains("SuccessRate"))
                {
                    
                    table2 = model.Tables["SONiCKusto"];
                }
                else
                {
                    table2 = model.Tables["PipelineRuns"];
                }

                string[] lines = File.ReadAllLines(txtFile);
                string measureName = "";
                string measureContent = "";
                foreach (string line in lines)
                {
                    if (line.StartsWith("======"))
                    {
                        if (measureName != "" && measureContent != "")
                        {

                            // Save the measure to the model
                            if (table2.Measures.ContainsName(measureName))
                            {
                                Console.WriteLine($"measure exists! {measureName}");
                                Measure measure = table2.Measures[measureName];
                                Console.WriteLine($"measure name! {measure.Name}");
                                measure.Expression = measureContent;
                            }
                            else
                            {
                                Measure measure = new Measure()
                                {
                                    Name = measureName,
                                    Expression = measureContent
                                };
                                Console.WriteLine($"measureName : {measure.Name}");
                                Console.WriteLine($"measureContent : {measure.Expression}");
                                table2.Measures.Add(measure);
                            }
                        }
                        // Reset the measure name and content
                        measureName = "";
                        measureContent = "";
                    }
                    else if (measureName == "")
                    {
                        // Set the measure name to the first line of the content
                        measureName = line;
                    }
                    else
                    {
                        // Append the line to the measure content
                        measureContent += line + "\n";
                    }
                }
            }

            model.SaveChanges();

        }
    }
}
