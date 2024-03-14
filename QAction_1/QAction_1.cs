namespace Skyline.Protocol
{
    using System;
    using System.Collections.Generic;
    using PacketDotNet;
    using System.Threading.Tasks;
    using SharpPcap;
    using Skyline.DataMiner.Scripting;
    using System.Linq;

    public class MyClass
    {
        public string RetrieveNetworkInterfaces()
        {
            // Retrieve the device list
            var devices = CaptureDeviceList.Instance;

            // If no devices were found, return an error message
            if (devices.Count < 1)
            {
                return "No capture devices were found. Make sure WinPcap is installed.";
            }

            // Concatenate descriptions into a single string separated by semicolons
            string interfaceList = string.Join(";", devices.Select(device => device.Description));

            return interfaceList;
        }


    }
}
