using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using Skyline.DataMiner.Net.VirtualFunctions;
using Skyline.DataMiner.Scripting;
using SLNetMessages = Skyline.DataMiner.Net.Messages;

/// <summary>
/// DataMiner QAction Class: Add row to Table 70.
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



            // Add row to table 70 



            string[] param_80 = Convert.ToString(protocol.GetParameter(80)).Split(':'); /// 172.16.8.50:5004:1345


            string sourceAddress = param_80[0];
            string sourcePort = param_80[1];
            string packetSize = param_80[2];

            


            object[] col_1_sourceIPS = (object[])((object[])protocol.NotifyProtocol((int)SLNetMessages.NotifyType.NT_GET_TABLE_COLUMNS, 70, new uint[] { 1 }))[0];

            object[] col_2_sourcePorts = (object[])((object[])protocol.NotifyProtocol((int)SLNetMessages.NotifyType.NT_GET_TABLE_COLUMNS, 70, new uint[] { 2 }))[0];

            var isExist = true;


            if (col_1_sourceIPS.Length >= 1)
            {

                for (int i = 0; i < col_1_sourceIPS.Length; i++)
                {


 

                    if (Convert.ToString(col_1_sourceIPS[i]) == sourceAddress)
                    {
                        //protocol.SetParameter(80, "returnnnn");

                        if (Convert.ToString(col_2_sourcePorts[i]) == sourcePort)
                        {
                            isExist = true;
                            break;
                        }
                        else
                        {
                            isExist = false;

                        }
                    }
                    else
                    {
                        isExist = false;

                    }

                }


               



            }
            else if (col_1_sourceIPS.Length == 0)
            {

                isExist = false;


            }




            if (isExist == false)
            {
                var row = new MulticastanalyzertableQActionRow()
                {
                    Sourceip_72 = sourceAddress,
                    Sourceport_73 = sourcePort,
                     Length_74 = packetSize
                };


                protocol.AddRow(70, row);
            }






        }
		catch (Exception ex)
		{
			protocol.Log($"QA{protocol.QActionID}|{protocol.GetTriggerParameter()}|Run|Exception thrown:{Environment.NewLine}{ex}", LogType.Error, LogLevel.NoLogging);
		}
	}
}