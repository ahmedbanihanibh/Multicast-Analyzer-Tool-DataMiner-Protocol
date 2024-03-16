using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using Skyline.Protocol;
using Skyline.DataMiner.Scripting;
/// <summary>
/// DataMiner QAction Class: After Startup.
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


            // Delete All Nodes in table PID __70
            protocol.ClearAllKeys(Parameter.Multicastanalyzertable.tablePid);


            // Instantiate MyNewAction to access RetrieveNetworkInterfaces method
            var myNewAction = new MyClass();

            // Call RetrieveNetworkInterfaces method
            string networkInterfaces = myNewAction.RetrieveNetworkInterfaces();


            protocol.SetParameter(12, networkInterfaces);


        }
        catch (Exception ex)
        {
            protocol.Log($"QA{protocol.QActionID}|{protocol.GetTriggerParameter()}|Run|Exception thrown:{Environment.NewLine}{ex}", LogType.Error, LogLevel.NoLogging);
        }
    }
}
