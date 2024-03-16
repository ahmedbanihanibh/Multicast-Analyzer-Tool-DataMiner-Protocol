using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using Skyline.Protocol;
using Skyline.DataMiner.Scripting;
using System.Collections.Generic;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Linq;
using System.Threading.Tasks;
 using SLNetMessages = Skyline.DataMiner.Net.Messages;

/// <summary>
/// DataMiner QAction Class: Start Analyzing Multicast Source IP.
/// </summary>
public static class QAction
{
    // Define class-level static variables to store accumulated packet size and time
    private static DateTime lastPacketTime = DateTime.Now;
    /// <summary>
    /// The QAction entry point.
    /// </summary>
    /// <param name="protocol">Link with SLProtocol process.</param>
    public static void Run(SLProtocol protocol)
	{
		try
		{
 

            // Delete All Nodes in table PID 70
            protocol.ClearAllKeys(Parameter.Multicastanalyzertable.tablePid);

            string nic = Convert.ToString(protocol.GetParameter(10));
            string mc_ip = Convert.ToString(protocol.GetParameter(20));
            int mc_port = Convert.ToInt32(protocol.GetParameter(30));
            int timeout = Convert.ToInt32(protocol.GetParameter(40));
            int testDuration = Convert.ToInt32(protocol.GetParameter(41));

            TimeSpan duration = TimeSpan.FromSeconds(testDuration);

            var myNewAction = new MyClass();

            // Call DetectMulticast method
 
             DetectMulticastAsync(mc_ip, mc_port, nic, duration, timeout, protocol);



        }
		catch (Exception ex)
		{
			protocol.Log($"QA{protocol.QActionID}|{protocol.GetTriggerParameter()}|Run|Exception thrown:{Environment.NewLine}{ex}", LogType.Error, LogLevel.NoLogging);
		}



	}/// void

 
    public static async Task DetectMulticastAsync(string multicastAddress, int multicastPort, string interfaceName, TimeSpan duration, int timeoutInSeconds, SLProtocol protocol)
    {
 
    // Keep track of source IPs for each multicast IP
    var sourceIpsByMulticastIp = new Dictionary<string, Dictionary<string, DateTime>>();

        // Retrieve the device list
        var devices = CaptureDeviceList.Instance;

        // Find the selected network interface
        var selectedDevice = devices.FirstOrDefault(device => device.Description == interfaceName);

        // If no devices were found or interface not found, print an error
        if (selectedDevice == null)
        {
            protocol.SetParameter(90, -2); //Error
            protocol.SetParameter(80, "Invalid network interface name or no such interface found."); //Details

            //Console.WriteLine("Invalid network interface name or no such interface found.");
            return;
        }

        // Open the selected device for capturing
        try
        {
            selectedDevice.Open(DeviceMode.Promiscuous);
            protocol.SetParameter(51, 1); //Status Running
        }
        catch (Exception ex)
        {
          //  Console.WriteLine($"Error opening device: {ex.Message}");
            protocol.SetParameter(90, -2); //Error
            protocol.SetParameter(80, $"Error opening device: {ex.Message}"); //Details
            return;
        }

        // Set a packet filter to capture only the specified multicast traffic
        try
        {
            selectedDevice.Filter = $"ip and udp and host {multicastAddress} and port {multicastPort}";
        }
        catch (Exception ex)
        {
           // Console.WriteLine($"Error setting packet filter: {ex.Message}");
            protocol.SetParameter(90, -2); //Error
            protocol.SetParameter(80, $"Error setting packet filter: {ex.Message}"); //Details
            selectedDevice.Close(); // Close the device in case of an error
            return;
        }

        DateTime functionEndTime = DateTime.Now + duration; // Calculate end time for the function


        //Start process 
        protocol.SetParameter(90, 0);

        // Start the capture process
        selectedDevice.OnPacketArrival += (object sender, CaptureEventArgs e) =>
        {
            // Parse the packet
            var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);

            // Get the IP packet
            var ipPacket = packet.Extract<IPPacket>();

            // If the IP packet is null, ignore
            if (ipPacket == null)
            {

                return;
            }

            var destinationAddress = ipPacket.DestinationAddress.ToString();
            var sourceAddress = ipPacket.SourceAddress.ToString();


 
            int packetSize = e.Packet.Data.Length; // Assuming e.Packet.Data contains the packet data
            //byte[] packetData = e.Packet.Data;  
 




            int sourcePort = 0;

            // Check if the packet is TCP
            var tcpPacket = ipPacket.PayloadPacket as TcpPacket;
            if (tcpPacket != null)
            {
                sourcePort = tcpPacket.SourcePort;
            }



            string payloadString = "";


            // If it's not TCP, check if it's UDP
            if (tcpPacket == null)
            {
                var udpPacket = ipPacket.PayloadPacket as UdpPacket;
               // payloadString = Encoding.ASCII.GetString(ipPacket.Bytes);
                if (udpPacket != null)
                {
                    sourcePort = udpPacket.SourcePort;
                }
            }

            // Check if we've seen this multicast IP before
            if (!sourceIpsByMulticastIp.ContainsKey(destinationAddress))
            {
                sourceIpsByMulticastIp[destinationAddress] = new Dictionary<string, DateTime>();
            }


            // Combine source address and port into a single key
            var sourceKey = $"{sourceAddress}:{sourcePort}:{packetSize}";

            // Update or add the source IP and port with the current timestamp
            sourceIpsByMulticastIp[destinationAddress][sourceKey] = DateTime.Now;


            // Update or add the source IP and port with the current timestamp
             sourceIpsByMulticastIp[destinationAddress][sourceKey] = DateTime.Now;
















            if (sourceIpsByMulticastIp[destinationAddress].Count < 1)
            {

                protocol.SetParameter(90, 0);
                //  protocol.SetParameter(80,payloadData);


                // Check if there it not added into Table then add it table no.70

            }

            if (sourceIpsByMulticastIp[destinationAddress].Count == 1)
            {

                protocol.SetParameter(90, 1);
                protocol.SetParameter(80, sourceKey);

            }

            if (sourceIpsByMulticastIp[destinationAddress].Count == 2)
            {

                protocol.SetParameter(90, 2);
                protocol.SetParameter(80, sourceKey);

            }

            // If more than 2 source is transmitting on the same multicast IP, print a warning
            if (sourceIpsByMulticastIp[destinationAddress].Count > 2)
            {


                protocol.SetParameter(90, 3);
                protocol.SetParameter(80, sourceKey);


            }




            /*

            if (sourceIpsByMulticastIp[destinationAddress].Count >= 1)
            {





                object[] col_1_sourceIPS  = (object[])((object[])protocol.NotifyProtocol((int)SLNetMessages.NotifyType.NT_GET_TABLE_COLUMNS, 70, new uint[] { 1 }))[0];

                object[] col_1_sourcePorts = (object[])((object[])protocol.NotifyProtocol((int)SLNetMessages.NotifyType.NT_GET_TABLE_COLUMNS, 70, new uint[] { 2 }))[0];


                if(col_1_sourceIPS.Length > 0)
                {

                    col_1_sourceIPS = (object[])((object[])protocol.NotifyProtocol((int)SLNetMessages.NotifyType.NT_GET_TABLE_COLUMNS, 70, new uint[] { 1 }))[0];
                    col_1_sourcePorts = (object[])((object[])protocol.NotifyProtocol((int)SLNetMessages.NotifyType.NT_GET_TABLE_COLUMNS, 70, new uint[] { 2 }))[0];

                    protocol.SetParameter(83, $"{col_1_sourceIPS.Length}_{DateTime.Now}_Tester: {Convert.ToString(col_1_sourceIPS[col_1_sourceIPS.Length -1])}:{Convert.ToInt32(col_1_sourcePorts[col_1_sourceIPS.Length - 1])}");

                    for (int i = 0; i < col_1_sourcePorts.Length; i++)
                        {



                            if (Convert.ToString(col_1_sourceIPS[i]) == sourceAddress && Convert.ToInt32(col_1_sourcePorts[i]) == sourcePort)

                            {
                                return;
                            }
                            else
                            {

                            //Add the row
                            var row = new MulticastanalyzertableQActionRow()
                                {
                                    // Multicastanalyzertable_index_71 = "1",
                                    Sourceip_72 = sourceAddress,
                                    Sourceport_73 = sourcePort,
                                    Bitrate_74 = packetSize * 8,
                                };

                                protocol.AddRow(70, row);


                            //update table row data



                        }




                    }



                }
                else
                {

                    protocol.SetParameter(83, $"ELSE__{col_1_sourceIPS.Length}_{DateTime.Now}_Tester: {Convert.ToString(col_1_sourceIPS[col_1_sourceIPS.Length - 1])}:{Convert.ToInt32(col_1_sourcePorts[col_1_sourceIPS.Length - 1])}");


                    //Add the row
                    var row = new MulticastanalyzertableQActionRow()
                    {
                        // Multicastanalyzertable_index_71 = "1",
                        Sourceip_72 = sourceAddress,
                        Sourceport_73 = sourcePort,
                        Bitrate_74 = packetSize * 8,
                    };

                    protocol.AddRow(70, row);
                }


               


            }


            */




        };

        // Start the capture process
        selectedDevice.StartCapture();

        // Inside your DetectMulticast method

        // Define an asynchronous method for monitoring function duration
        async Task MonitorFunctionDurationAsync()
        {
            var runningTask = Convert.ToInt32(protocol.GetParameter(51));  //sattus

            while (DateTime.Now < functionEndTime && runningTask == 1)
            {


                if(runningTask != 1)
                { 
                    break; }

                // Calculate elapsed time since the last packet
                foreach (var multicastEntry in sourceIpsByMulticastIp)
                {
                    var sourcesToRemove = new List<string>();

                    foreach (var sourceEntry in multicastEntry.Value)
                    {
                        if ((DateTime.Now - sourceEntry.Value).TotalSeconds > timeoutInSeconds)
                        {
                            sourcesToRemove.Add(sourceEntry.Key);
                        }
                    }

                    foreach (var sourceToRemove in sourcesToRemove)
                    {
                        multicastEntry.Value.Remove(sourceToRemove);

                        // seach for this row and delete it
                        object[] col_1_index = (object[])((object[])protocol.NotifyProtocol((int)SLNetMessages.NotifyType.NT_GET_TABLE_COLUMNS, 70, new uint[] { 0 }))[0];

                        object[] col_1_ip = (object[])((object[])protocol.NotifyProtocol((int)SLNetMessages.NotifyType.NT_GET_TABLE_COLUMNS, 70, new uint[] { 1 }))[0];
                        object[] col_2_port = (object[])((object[])protocol.NotifyProtocol((int)SLNetMessages.NotifyType.NT_GET_TABLE_COLUMNS, 70, new uint[] { 2 }))[0];

                        int counter = col_1_ip.Length;



                        if( counter <=3 )
                        {
                            int param_90 = Convert.ToInt32(protocol.GetParameter(90));
                            protocol.SetParameter(90, param_90 - 1);

                        }





                        /// find the key then delete it 


                        string[] lines = sourceToRemove.Split(':');

                        string sAdd = lines[0];
                        string sPort = lines[1];
                        string sPacket = lines[2];


                        var row = new MulticastanalyzertableQActionRow()
                        {
                            Sourceip_72 = sAdd,
                            Sourceport_73 = sPort,
                             Length_74 = sPacket
                        };




                        string rowKey = string.Empty;

                        for (int i = 0; i< counter;i++)
                        {
                                if (Convert.ToString(col_1_ip[i]) == sAdd && Convert.ToString(col_2_port[i]) == sPort)
                                  {

                                rowKey = Convert.ToString(col_1_index[i]);

                                  }
                         }




                        if (!string.IsNullOrEmpty(rowKey))
                            protocol.DeleteRow(70, rowKey);








                    }
                }

                await Task.Delay(100); // Asynchronously delay for 100 milliseconds before checking again

                //update running Task
                runningTask = Convert.ToInt32(protocol.GetParameter(51));  //status


            }
        }

        // Start the asynchronous method in a separate task and wait for it to complete
        Task monitorTask = MonitorFunctionDurationAsync();
        await monitorTask; // Wait for the background task to complete before continuing

        // Continue with the rest of your code
        // Stop the capture process after function duration
        selectedDevice.StopCapture();
        selectedDevice.Close(); // Close the device
        protocol.SetParameter(51, 2); //Status Not Running
        protocol.SetParameter(90, -3); // Finished

    }




    //////////////////////
}