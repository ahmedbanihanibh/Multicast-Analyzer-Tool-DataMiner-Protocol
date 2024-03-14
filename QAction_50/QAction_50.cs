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
using System.Threading;
using System.Linq;
using System.Threading.Tasks;

/// <summary>
/// DataMiner QAction Class: Start Analyzing Multicast Source IP.
/// </summary>
public static class QAction
{
	/// <summary>
	/// The QAction entry point.
	/// </summary>
	/// <param name="protocol">Link with SLProtocol process.</param>
	public static void Run(SLProtocol protocol)
	{
		try
		{

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
            int sourcePort = 0;

            // Check if the packet is TCP
            var tcpPacket = ipPacket.PayloadPacket as TcpPacket;
            if (tcpPacket != null)
            {
                sourcePort = tcpPacket.SourcePort;
            }

            // If it's not TCP, check if it's UDP
            if (tcpPacket == null)
            {
                var udpPacket = ipPacket.PayloadPacket as UdpPacket;
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
            var sourceKey = $"{sourceAddress}:{sourcePort}";

            // Update or add the source IP and port with the current timestamp
            sourceIpsByMulticastIp[destinationAddress][sourceKey] = DateTime.Now;


            // Update or add the source IP and port with the current timestamp
             sourceIpsByMulticastIp[destinationAddress][sourceKey] = DateTime.Now;


            if (sourceIpsByMulticastIp[destinationAddress].Count < 1)
            {

                protocol.SetParameter(90, 0);
              //  protocol.SetParameter(80,payloadData);

            }

            if (sourceIpsByMulticastIp[destinationAddress].Count == 1 )
            {

                protocol.SetParameter(90, 1);
                protocol.SetParameter(80, sourceKey);
 
            }


            // Print a message for each received packet
            //  string param_80 = Convert.ToString(protocol.GetParameter(80));
            //  param_80 += $"\r\n{DateTime.Now:HH:mm:ss.fff}: New source {sourceAddress} for multicast address {destinationAddress}";
            /// string param_80 = $"{DateTime.Now:HH:mm:ss.fff}: New source {sourceAddress} for multicast address {destinationAddress}";

            ///  protocol.SetParameter(80, param_80);

            // If more than one source is transmitting on the same multicast IP, print a warning
            if (sourceIpsByMulticastIp[destinationAddress].Count == 2)
            {
                // string param_80_2 = Convert.ToString(protocol.GetParameter(80));
                // param_80_2 += $"\r\n{DateTime.Now:HH:mm:ss.fff}: Warning: Multiple sources transmitting on multicast address {destinationAddress}";

                //// string param_80_2 = $"{DateTime.Now:HH:mm:ss.fff}: Warning: Multiple sources transmitting on multicast address {destinationAddress}";

                ////  protocol.SetParameter(80, param_80_2);
                ///

                protocol.SetParameter(90, 2);
              //  protocol.SetParameter(80, sourceAddress);


            }

            // If more than 2 source is transmitting on the same multicast IP, print a warning
            if (sourceIpsByMulticastIp[destinationAddress].Count > 2)
            {


                protocol.SetParameter(90, 3);

            }

        };

        // Start the capture process
        selectedDevice.StartCapture();

        // Inside your DetectMulticast method

        // Define an asynchronous method for monitoring function duration
        async Task MonitorFunctionDurationAsync()
        {
            while (DateTime.Now < functionEndTime)
            {
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
                        string param_80 = Convert.ToString(protocol.GetParameter(80));
                        param_80 += $"{DateTime.Now:HH:mm:ss.fff}: Removed inactive source {sourceToRemove} for multicast address {multicastEntry.Key}";
                        int param_90 = Convert.ToInt32(protocol.GetParameter(90));
                        protocol.SetParameter(90, param_90 - 1);
                    }
                }

                await Task.Delay(100); // Asynchronously delay for 100 milliseconds before checking again
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
        protocol.SetParameter(90, -1); // Off

    }




    //////////////////////
}