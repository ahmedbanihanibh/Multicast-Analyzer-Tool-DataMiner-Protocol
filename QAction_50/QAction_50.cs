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

            TimeSpan duration = TimeSpan.FromMinutes(1);

            var myNewAction = new MyClass();

            // Call DetectMulticast method
 
             DetectMulticast(mc_ip, mc_port, nic, duration, timeout, protocol);



        }
		catch (Exception ex)
		{
			protocol.Log($"QA{protocol.QActionID}|{protocol.GetTriggerParameter()}|Run|Exception thrown:{Environment.NewLine}{ex}", LogType.Error, LogLevel.NoLogging);
		}



	}/// void

    public static void DetectMulticast(string multicastAddress, int multicastPort, string interfaceName, TimeSpan duration, int timeoutInSeconds, SLProtocol protocol)
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
            Console.WriteLine("Invalid network interface name or no such interface found.");
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
            Console.WriteLine($"Error opening device: {ex.Message}");
            return;
        }

        // Set a packet filter to capture only the specified multicast traffic
        try
        {
            selectedDevice.Filter = $"ip and udp and host {multicastAddress} and port {multicastPort}";
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error setting packet filter: {ex.Message}");
            selectedDevice.Close(); // Close the device in case of an error
            return;
        }

        DateTime functionEndTime = DateTime.Now + duration; // Calculate end time for the function

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

            // Check if we've seen this multicast IP before
            if (!sourceIpsByMulticastIp.ContainsKey(destinationAddress))
            {
                sourceIpsByMulticastIp[destinationAddress] = new Dictionary<string, DateTime>();
            }

            // Update or add the source IP with the current timestamp
            sourceIpsByMulticastIp[destinationAddress][sourceAddress] = DateTime.Now;


            if (sourceIpsByMulticastIp[destinationAddress].Count < 1)
            {

                protocol.SetParameter(90, 0);
            }

            if (sourceIpsByMulticastIp[destinationAddress].Count == 1 )
            {

                protocol.SetParameter(90, 1);
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

            }

            // If more than 2 source is transmitting on the same multicast IP, print a warning
            if (sourceIpsByMulticastIp[destinationAddress].Count > 2)
            {


                protocol.SetParameter(90, 3);

            }

        };

        // Start the capture process
        selectedDevice.StartCapture();

        // Monitor for function duration
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
                    protocol.SetParameter(80, param_80);
                }
            }

            Thread.Sleep(100); // Sleep for 100 milliseconds before checking again
        }

        // Stop the capture process after function duration
        selectedDevice.StopCapture();
        selectedDevice.Close(); // Close the device
        protocol.SetParameter(51, 2); //Status Not Running
        protocol.SetParameter(90, -1); // Off

    }




    //////////////////////
}